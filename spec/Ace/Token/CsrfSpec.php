<?php namespace spec\Ace\Token;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class CsrfSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('Ace\Token\Csrf');
    }

    public function it_has_a_string_value()
    {
        $this->_toString()->shouldBeString();
    }

    public function it_should_not_be_empty()
    {
        $this->_toString()->shouldNotBeEqualTo('');
    }
}
