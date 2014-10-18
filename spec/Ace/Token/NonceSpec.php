<?php namespace spec\Ace\Token;

use Ace\Token\Nonce;
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
        $this->__toString()->shouldBeString();
    }

    public function it_should_not_be_empty()
    {
        $this->__toString()->shouldNotBeEqualTo('');
    }

    public function it_does_not_equal_other_nonce_token()
    {
        $other = new Nonce;
        $this->matches($other)->shouldNotBeEqualTo(true);
    }

    public function it_does_equal_own_nonce_token()
    {
        $token = $this->__toString();
        $this->matches($token)->shouldBeEqualTo(true);
    }
}
