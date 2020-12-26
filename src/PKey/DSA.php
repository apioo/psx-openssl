<?php
/*
 * PSX is a open source PHP framework to develop RESTful APIs.
 * For the current version and informations visit <http://phpsx.org>
 *
 * Copyright 2010-2016 Christoph Kappestein <k42b3.x@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace PSX\OpenSsl\PKey;

/**
 * DSA
 *
 * @author  Christoph Kappestein <k42b3.x@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    http://phpsx.org
 */
class DSA extends TypeAbstract
{
    /**
     * @var string
     */
    private $p;

    /**
     * @var string
     */
    private $q;

    /**
     * @var string
     */
    private $g;

    /**
     * @var string
     */
    private $privKey;

    /**
     * @var string
     */
    private $pubKey;


    /**
     * @param string $p
     * @param string $q
     * @param string $g
     * @param string $privKey
     * @param string $pubKey
     */
    public function __construct(int $bits, string $key, string $p, string $q, string $g, string $privKey, string $pubKey)
    {
        parent::__construct($bits, $key);
        
        $this->p = $p;
        $this->q = $q;
        $this->g = $g;
        $this->privKey = $privKey;
        $this->pubKey = $pubKey;
    }

    /**
     * @return string
     */
    public function getP(): string
    {
        return $this->p;
    }

    /**
     * @return string
     */
    public function getQ(): string
    {
        return $this->q;
    }

    /**
     * @return string
     */
    public function getG(): string
    {
        return $this->g;
    }

    /**
     * @return string
     */
    public function getPrivKey(): string
    {
        return $this->privKey;
    }

    /**
     * @return string
     */
    public function getPubKey(): string
    {
        return $this->pubKey;
    }

    public static function fromArray(array $details): self
    {
        return new self(
            $details['bits'] ?? '',
            $details['key'] ?? '',
            $details['rsa']['p'] ?? '',
            $details['rsa']['q'] ?? '',
            $details['rsa']['g'] ?? '',
            $details['rsa']['priv_key'] ?? '',
            $details['rsa']['pub_key'] ?? '',
        );
    }
}
