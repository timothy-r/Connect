<?php namespace Ace\Token;

class Nonce
{
    private $value;

    public function __construct($value = null)
    {
        if (is_null($value)){
            $this->value = hash('md5', rand());
        } else {
            $this->value = $value;
       }
    }

    public function __toString()
    {
        return $this->value;
    }

    public function matches($token)
    {
        return (string)$this == (string)$token;
    }
}
