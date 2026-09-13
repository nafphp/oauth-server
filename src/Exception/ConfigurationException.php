<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Exception;

use LogicException;

/**
 * The setup cannot work, and no request should be answered with it.
 *
 * Distinct from OAuthError on purpose: that one describes something a client or
 * a person did and belongs in a protocol response, this one describes something
 * the installation did and belongs in a log and a stack trace. Answering a
 * misconfiguration with a polite `invalid_request` would hide it.
 */
final class ConfigurationException extends LogicException
{
}
