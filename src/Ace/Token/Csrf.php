<?php namespace Ace\Token;

class Csrf
{
    private $value;
    
    public function __construct()
    {
        $this->value = hash('md5', rand());
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
