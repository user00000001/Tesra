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
package neovm

import (
	"fmt"
	"github.com/TesraSupernet/Tesra/core/utils"
	"reflect"

	"github.com/TesraSupernet/Tesra/common"
	"github.com/TesraSupernet/Tesra/core/payload"
	"github.com/TesraSupernet/Tesra/core/types"
	"github.com/TesraSupernet/Tesra/vm/crossvm_codec"
	vm "github.com/TesraSupernet/Tesra/vm/neovm"
)

//neovm contract call wasmvm contract
func WASMInvoke(service *NeoVmService, engine *vm.Executor) error {
	address, err := engine.EvalStack.PopAsBytes()
	if err != nil {
		return err
	}

	contractAddress, err := common.AddressParseFromBytes(address)
	if err != nil {
		return fmt.Errorf("invoke wasm contract:%s, address invalid", address)
	}

	dp, err := service.CacheDB.GetContract(contractAddress)
	if err != nil {
		return err
	}
	if dp == nil {
		return fmt.Errorf("wasm contract does not exist")
	}

	if dp.VmType() != payload.WASMVM_TYPE {
		return fmt.Errorf("not a wasm contract")
	}

	parambytes, err := engine.EvalStack.PopAsBytes()
	if err != nil {
		return err
	}
	list, err := crossvm_codec.DeserializeCallParam(parambytes)
	if err != nil {
		return err
	}

	params, ok := list.([]interface{})
	if ok == false {
		return fmt.Errorf("wasm invoke error: wrong param type:%s", reflect.TypeOf(list).String())
	}

	inputs, err := utils.BuildWasmVMInvokeCode(contractAddress, params)
	if err != nil {
		return err
	}

	newservice, err := service.ContextRef.NewExecuteEngine(inputs, types.InvokeWasm)
	if err != nil {
		return err
	}

	tmpRes, err := newservice.Invoke()
	if err != nil {
		return err
	}

	return engine.EvalStack.PushBytes(tmpRes.([]byte))
}
