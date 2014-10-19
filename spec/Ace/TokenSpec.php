<?php namespace spec\Ace;

use Ace\Token;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class TokenSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('Ace\Token');
    }

    public function it_has_a_string_value()
    {
        $this->__toString()->shouldBeString();
    }

    public function it_should_not_be_empty()
    {
        $this->__toString()->shouldNotBeEqualTo('');
    }

    public function it_does_not_equal_other_token()
    {
        $other = new Token;
        $this->matches($other)->shouldNotBeEqualTo(true);
    }

    public function it_does_equal_own_token()
    {
        $token = $this->__toString();
        $this->matches($token)->shouldBeEqualTo(true);
    }

    public function it_can_be_created_with_a_value()
    {
        $value = 'abc123';
        $this->beConstructedWith($value);
        $this->__toString()->shouldBeEqualTo($value);
    }
}
