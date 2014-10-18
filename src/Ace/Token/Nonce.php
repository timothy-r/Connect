<?php namespace Ace\Token;

class Nonce
{
    private $value = 'a unique once ever string';

    public function _toString()
    {
        return $this->value;
    }
}
