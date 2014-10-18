<?php namespace Ace\Token;

class Nonce
{
    private $value = 'a unique once ever string';

    public function __toString()
    {
        return $this->value;
    }
}
