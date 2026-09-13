<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Support;

/**
 * Render one of this plugin's views.
 *
 * With nixphp/view installed this goes through its template resolution, which is
 * what lets an application shadow the consent screen with its own. Without it,
 * the shipped template is rendered directly — same markup, no override.
 */
final class Views
{
    /** @param array<string, mixed> $variables */
    public static function render(string $template, array $variables): string
    {
        if (function_exists('NixPHP\View\view')) {
            return \NixPHP\View\view($template, $variables);
        }

        extract($variables);
        ob_start();
        include dirname(__DIR__) . '/views/' . str_replace('.', '/', $template) . '.phtml';

        return (string) ob_get_clean();
    }
}
