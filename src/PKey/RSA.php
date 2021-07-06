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
 * RSA
 *
 * @author  Christoph Kappestein <k42b3.x@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    http://phpsx.org
 */
class RSA extends TypeAbstract
{
    /**
     * @var string
     */
    private $n;

    /**
     * @var string
     */
    private $e;

    /**
     * @var string
     */
    private $d;

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
    private $dmp1;

    /**
     * @var string
     */
    private $dmq1;

    /**
     * @var string
     */
    private $iqmp;

    /**
     * @param string $n
     * @param string $e
     * @param string $d
     * @param string $p
     * @param string $q
     * @param string $dmp1
     * @param string $dmq1
     * @param string $iqmp
     */
    public function __construct(int $bits, string $key, string $n, string $e, string $d, string $p, string $q, string $dmp1, string $dmq1, string $iqmp)
    {
        parent::__construct($bits, $key);
        
        $this->n = $n;
        $this->e = $e;
        $this->d = $d;
        $this->p = $p;
        $this->q = $q;
        $this->dmp1 = $dmp1;
        $this->dmq1 = $dmq1;
        $this->iqmp = $iqmp;
    }

    /**
     * @return string
     */
    public function getN(): string
    {
        return $this->n;
    }

    /**
     * @return string
     */
    public function getE(): string
    {
        return $this->e;
    }

    /**
     * @return string
     */
    public function getD(): string
    {
        return $this->d;
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
    public function getDmp1(): string
    {
        return $this->dmp1;
    }

    /**
     * @return string
     */
    public function getDmq1(): string
    {
        return $this->dmq1;
    }

    /**
     * @return string
     */
    public function getIqmp(): string
    {
        return $this->iqmp;
    }

    public static function fromArray(array $details): self
    {
        return new self(
            $details['bits'] ?? 0,
            $details['key'] ?? '',
            $details['rsa']['n'] ?? '',
            $details['rsa']['e'] ?? '',
            $details['rsa']['d'] ?? '',
            $details['rsa']['p'] ?? '',
            $details['rsa']['q'] ?? '',
            $details['rsa']['dmp1'] ?? '',
            $details['rsa']['dmq1'] ?? '',
            $details['rsa']['iqmp'] ?? '',
        );
    }
}
