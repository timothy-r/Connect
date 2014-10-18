<?php namespace Ace\OpenId;

use Ace\Token\Csrf;

class Connect
{
    public function generateCsrfToken()
    {
        return new Csrf;
    }
}
