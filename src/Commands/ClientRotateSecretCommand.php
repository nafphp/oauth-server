<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Commands;

use InvalidArgumentException;
use Naf\CLI\Core\{AbstractCommand, Input, Output};
use Naf\OAuth\Server\Store\ClientStoreInterface;
use function Naf\app;

/**
 * Give a client a new secret without giving it a new identity.
 *
 * The reason this is a command of its own, and not "revoke and register again",
 * is the client id. Replacing a client changes it, which means editing every
 * configuration that names it and losing everything already issued. Rotating
 * changes only the secret, and nothing that was authorized notices.
 *
 * By default the secret being replaced keeps working for a day, because the new
 * one exists here before it exists wherever it is deployed. --now ends it
 * immediately, which is what a leak calls for: the client stops working until it
 * is redeployed, and that is the point.
 */
class ClientRotateSecretCommand extends AbstractCommand
{
    public const string NAME = 'oauth:client:rotate-secret';

    /** Long enough to deploy in, short enough that nobody forgets it is open. */
    private const int DEFAULT_OVERLAP = 86400;

    protected function configure(): void
    {
        $this
            ->setTitle('Rotate a client secret')
            ->setDescription('Issue a new secret for a client, keeping the old one valid for a while.')
            ->addArgument('client')
            ->addOption('overlap', 'o', expectsValue: true)
            ->addOption('now', 'n');
    }

    public function run(Input $input, Output $output): int
    {
        $clientId = $input->getArgument('client');

        if ($clientId === null || trim($clientId) === '') {
            $output->writeLine('Name the client: naf ' . self::NAME . ' <client-id>', 'error');

            return self::ERROR;
        }

        $configured = $input->getOption('overlap');
        $immediate  = $input->getOption('now') !== null;

        if ($immediate && is_string($configured)) {
            $output->writeLine('Give an overlap or --now, not both.', 'error');

            return self::ERROR;
        }

        if (!$immediate && $configured !== null && !(is_string($configured) && ctype_digit($configured))) {
            $output->writeLine('The overlap is a number of seconds.', 'error');

            return self::ERROR;
        }

        $overlap = match (true) {
            $immediate              => 0,
            is_string($configured)  => (int) $configured,
            default                 => self::DEFAULT_OVERLAP,
        };

        try {
            [$client, $secret] = app()->container()->get(ClientStoreInterface::class)
                ->rotateSecret(trim($clientId), $overlap);
        } catch (InvalidArgumentException $e) {
            $output->writeLine($e->getMessage(), 'error');

            return self::ERROR;
        }

        $output->writeEmptyLine();
        $output->writeLine('  ' . $client->name, 'ok');
        $output->writeLine('  ' . str_pad('Client ID', 16) . $client->id . ' (unchanged)');
        $output->writeLine('  ' . str_pad('New secret', 16) . $secret);
        $output->writeEmptyLine();
        $output->writeLine('  Copy the secret now. It is stored only as a hash and cannot be shown again.');

        $output->writeLine($overlap === 0
            ? '  The previous secret stopped working just now.'
            : '  The previous secret keeps working until '
              . date('Y-m-d H:i:s', (int) $client->previousSecretExpiresAt)
              . ' (' . $overlap . 's). Deploy the new one before then.',
            $overlap === 0 ? 'warning' : null);

        $output->writeEmptyLine();

        return self::SUCCESS;
    }
}
