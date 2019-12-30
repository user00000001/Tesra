/*
 * Copyright (C) 2019 The TesraSupernet Authors
 * This file is part of The TesraSupernet library.
 *
 * The TesraSupernet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The TesraSupernet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The TesraSupernet.  If not, see <http://www.gnu.org/licenses/>.
 */

package states

import (
	"io"

	"github.com/TesraSupernet/Tesra/common"
)

type WasmContractParam struct {
	Address common.Address
	Args    []byte
}

func (this *WasmContractParam) Serialization(sink *common.ZeroCopySink) {
	sink.WriteAddress(this.Address)
	sink.WriteVarBytes([]byte(this.Args))
}

// `ContractInvokeParam.Args` has reference of `source`
func (this *WasmContractParam) Deserialization(source *common.ZeroCopySource) error {
	var irregular, eof bool
	this.Address, eof = source.NextAddress()

	this.Args, _, irregular, eof = source.NextVarBytes()
	if irregular {
		return common.ErrIrregularData
	}
	if eof {
		return io.ErrUnexpectedEOF
	}
	return nil
}
