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
 * EC
 *
 * @author  Christoph Kappestein <k42b3.x@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    http://phpsx.org
 */
class EC extends TypeAbstract
{
    /**
     * @var string
     */
    private $curveName;

    /**
     * @var string
     */
    private $curveOid;

    /**
     * @var string
     */
    private $x;

    /**
     * @var string
     */
    private $y;

    /**
     * @var string
     */
    private $d;

    /**
     * @param string $curveName
     * @param string $curveOid
     * @param string $x
     * @param string $y
     * @param string $d
     */
    public function __construct(int $bits, string $key, string $curveName, string $curveOid, string $x, string $y, string $d)
    {
        parent::__construct($bits, $key);
        
        $this->curveName = $curveName;
        $this->curveOid = $curveOid;
        $this->x = $x;
        $this->y = $y;
        $this->d = $d;
    }

    /**
     * @return string
     */
    public function getCurveName(): string
    {
        return $this->curveName;
    }

    /**
     * @return string
     */
    public function getCurveOid(): string
    {
        return $this->curveOid;
    }

    /**
     * @return string
     */
    public function getX(): string
    {
        return $this->x;
    }

    /**
     * @return string
     */
    public function getY(): string
    {
        return $this->y;
    }

    /**
     * @return string
     */
    public function getD(): string
    {
        return $this->d;
    }

    public static function fromArray(array $details): self
    {
        return new self(
            $details['bits'] ?? '',
            $details['key'] ?? '',
            $details['curve_name'] ?? '',
            $details['curve_oid'] ?? '',
            $details['x'] ?? '',
            $details['y'] ?? '',
            $details['d'] ?? ''
        );
    }
}
