<?php namespace Ace\OpenId;

use Ace\Token\Csrf;
use Ace\Token\Nonce;

class Connect
{
    public function generateCsrfToken()
    {
        return new Csrf;
    }

    public function generateNonceToken()
    {
        return new Nonce;
    }
}
