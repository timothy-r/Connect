<?php namespace Ace\Token;

class Csrf
{
    private $value = 'sss';

    public function _toString()
    {
        return $this->value;
    }
}
