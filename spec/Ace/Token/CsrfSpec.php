<?php namespace spec\Ace\Token;

use Ace\Token\Csrf;
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
        $this->__toString()->shouldBeString();
    }

    public function it_should_not_be_empty()
    {
        $this->__toString()->shouldNotBeEqualTo('');
    }

    public function it_does_not_equal_other_csrf_token()
    {
        $other = new Csrf;
        $this->matches($other)->shouldNotBeEqualTo(true);
    }

    public function it_does_equal_own_csrf_token()
    {
        $token = $this->__toString();
        $this->matches($token)->shouldBeEqualTo(true);
    }
}
