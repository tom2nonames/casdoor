// Copyright 2023 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {Select} from "antd";
import * as Setting from "../Setting";
import React from "react";

const {Option} = Select;

export default function PhoneNumberInput(props) {
  const {onChange, style, showSearch} = props;
  const value = props.value ?? "CN";
  const countryCodes = props.countryCodes ?? [];

  const handleOnChange = (e) => {
    onChange?.(e);
  };

  return (
    <Select
      virtual={false}
      style={style}
      value={value}
      dropdownMatchSelectWidth={false}
      optionLabelProp={"label"}
      showSearch={showSearch}
      onChange={handleOnChange}
      filterOption={(input, option) =>
        (option?.label ?? "").toLowerCase().includes(input.toLowerCase())
      }
    >
      {
        Setting.getCountriesData(countryCodes).map((country) => (
          <Option key={country.code} value={country.code} label={`+${country.phone}`} >
            <div style={{display: "flex", justifyContent: "space-between"}}>
              <div>
                {Setting.countryFlag(country)}
                {`${country.name}`}
              </div>
              {`+${country.phone}`}
            </div>
          </Option>
        ))
      }
    </Select>
  );
}
