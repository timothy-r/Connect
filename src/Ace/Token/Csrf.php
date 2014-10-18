<?php namespace Ace\Token;

class Csrf
{
    private $value = '';

    public function _toString()
    {
        return $this->value;
    }
}
