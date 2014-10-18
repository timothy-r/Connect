<?php

namespace spec\Ace\Token;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class NonceSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('Ace\Token\Nonce');
    }

    public function it_has_a_string_value()
    {
        $this->_toString()->shouldBeString();
    }
}
