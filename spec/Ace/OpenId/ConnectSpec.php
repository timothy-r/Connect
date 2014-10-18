<?php

namespace spec\Ace\OpenId;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ConnectSpec extends ObjectBehavior
{
    public function it_is_initializable()
    {
        $this->shouldHaveType('Ace\OpenId\Connect');
    }

    public function it_generates_csrf_token()
    {
        $this->generateCsrfToken()->shouldHaveType('Ace\Token\Csrf');
    }

    public function it_generates_nonce_token()
    {
        $this->generateNonceToken()->shouldHaveType('Ace\Token\Nonce');
    }
}
