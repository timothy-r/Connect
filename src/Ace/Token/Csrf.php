<?php namespace Ace\Token;

class Csrf
{
    private $value = 'sss';

    public function __toString()
    {
        return $this->value;
    }

    public function matches($token)
    {
        return (string)$this == (string)$token;
    }
}
