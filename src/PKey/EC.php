<?php
/*
 * PSX is an open source PHP framework to develop RESTful APIs.
 * For the current version and information visit <https://phpsx.org>
 *
 * Copyright 2010-2022 Christoph Kappestein <christoph.kappestein@gmail.com>
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
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    https://phpsx.org
 */
class EC extends TypeAbstract
{
    private string $curveName;
    private string $curveOid;
    private string $x;
    private string $y;
    private string $d;

    public function __construct(int $bits, string $key, string $curveName, string $curveOid, string $x, string $y, string $d)
    {
        parent::__construct($bits, $key);
        
        $this->curveName = $curveName;
        $this->curveOid = $curveOid;
        $this->x = $x;
        $this->y = $y;
        $this->d = $d;
    }

    public function getCurveName(): string
    {
        return $this->curveName;
    }

    public function getCurveOid(): string
    {
        return $this->curveOid;
    }

    public function getX(): string
    {
        return $this->x;
    }

    public function getY(): string
    {
        return $this->y;
    }

    public function getD(): string
    {
        return $this->d;
    }

    public static function fromArray(array $details): self
    {
        return new self(
            $details['bits'] ?? 0,
            $details['key'] ?? '',
            $details['ec']['curve_name'] ?? '',
            $details['ec']['curve_oid'] ?? '',
            $details['ec']['x'] ?? '',
            $details['ec']['y'] ?? '',
            $details['ec']['d'] ?? ''
        );
    }
}
