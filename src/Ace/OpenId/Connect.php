<?php namespace Ace\OpenId;

use Lcobucci\JWT\Parser as JWTParser;
use Ace\OpenId\ResponseException;

use Ace\Token;
use Ace\Session;
use Ace\StoreInterface;

class Connect
{
    private static $issuer = 'https://my.domain.com';

    private static $client_id = 'Client';

    private static $client_key = '13d63cd20abaabdc148c46fc71566636';

    private $session;
    
    private $nonce_store;
    
    private $id_token_parser;

    public function __construct(Session $session, StoreInterface $nonce_store, JWTParser $parser)
    {
        $this->session = $session;
        $this->nonce_store = $nonce_store;
        $this->id_token_parser = $parser;
    }

    public function localTokensExist()
    {
        return $this->session->has('authn.csrf.token') && $this->session->has('authn.nonce.token');
    }

    /**
    * Get all the parameters to make a request to central authn
    * @return array
    */
    public function generateRequestParameters($redirect_uri)
    {
        return [
            'response_type' => 'id_token token',
            'client_id' => self::$client_id,
            'redirect_uri' => $redirect_uri,
            'scope' => 'openid',
            'state' => $this->generateCsrfToken(),
            'nonce' => $this->generateNonceToken(),
        ];
    }
    
    /**
    * validate necessary response parameters are set and have correct values
    */
    public function validateResponseParameters(array $parameters)
    {
        // validate that expected keys are set
        $required_keys = ['access_token', 'token_type', 'id_token', 'nonce', 'state'];
        foreach ($required_keys as $key) {
            if (!isset($parameters[$key])){
                throw new ResponseException("'$key' parameter must be set");
            }
        }
    
        // validate key values
        if (!$this->validateTokenType($parameters['token_type'])){
            throw new ResponseException("'token_type' parameter is invalid");
        }

        if (!$this->validateCsrfToken(new Token($parameters['state']))){
            throw new ResponseException("'state' parameter is invalid");
        }

        if (!$this->validateNonceToken(new Token($parameters['nonce']))){
            throw new ResponseException("'nonce' parameter is invalid");
        }

        // add the new nonce value to the store to prevent it being used again
        $this->nonce_store->add($parameters['nonce']);

        if (!$this->validateIdToken($parameters['id_token'])){
            throw new ResponseException("'id_token' parameter is invalid");
        }

        return true;
    }
    
    private function validateIdToken($id_token)
    {
        $token  = $this->id_token_parser->parse($id_token);
        if (!$token->verify(self::$client_key)){
            return false;
        }

        $claims = $token->getClaims();
        if (!$token->validate(self::$issuer, self::$client_id, $claims['sub'])){
            return false;
        }
        return true;
    }

    private function validateTokenType($type) 
    {
        return 'bearer' == strtolower($type);
    }

    private function validateCsrfToken(Token $csrf)
    {
        return $csrf->matches($this->session->get('authn.csrf.token'));
    }

    private function validateNonceToken(Token $nonce)
    {
        if ($nonce->matches($this->session->get('authn.nonce.token'))){
            // check nonce hasn't been used before
            return !$this->nonce_store->contains($nonce);
        } else {
            return false;
        }
    }

    private function generateCsrfToken()
    {
        $csrf = new Token;
        $key = 'authn.csrf.token';
        $this->session->store($key, $csrf);
        return $csrf;
    }

    private function generateNonceToken()
    {
        $nonce = new Token;
        $key = 'authn.nonce.token';
        $this->session->store($key, $nonce);
        return $nonce;
    }
}
