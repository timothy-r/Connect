<?php namespace Ace;

interface StoreInterface
{
    public function contains($key);

    public function add($key);
}
