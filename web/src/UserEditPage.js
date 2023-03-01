// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

import React from "react";
import {Button, Card, Col, Input, Result, Row, Select, Spin, Switch} from "antd";
import * as UserBackend from "./backend/UserBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import CropperDiv from "./CropperDiv.js";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import PasswordModal from "./PasswordModal";
import ResetModal from "./ResetModal";
import AffiliationSelect from "./common/AffiliationSelect";
import OAuthWidget from "./common/OAuthWidget";
import SamlWidget from "./common/SamlWidget";
import SelectRegionBox from "./SelectRegionBox";
import WebAuthnCredentialTable from "./WebauthnCredentialTable";
import ManagedAccountTable from "./ManagedAccountTable";
import PropertyTable from "./propertyTable";
import PhoneNumberInput from "./common/PhoneNumberInput";

const {Option} = Select;

class UserEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      organizationName: props.organizationName !== undefined ? props.organizationName : props.match.params.organizationName,
      userName: props.userName !== undefined ? props.userName : props.match.params.userName,
      user: null,
      application: null,
      organizations: [],
      applications: [],
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
      loading: true,
      returnUrl: null,
    };
  }

  UNSAFE_componentWillMount() {
    this.getUser();
    this.getOrganizations();
    this.getApplicationsByOrganization(this.state.organizationName);
    this.getUserApplication();
    this.setReturnUrl();
  }

  getUser() {
    UserBackend.getUser(this.state.organizationName, this.state.userName)
      .then((data) => {
        if (data.status === null || data.status !== "error") {
          this.setState({
            user: data,
          });
        }
        this.setState({
          loading: false,
        });
      });
  }

  getOrganizations() {
    OrganizationBackend.getOrganizations("admin")
      .then((res) => {
        this.setState({
          organizations: (res.msg === undefined) ? res : [],
        });
      });
  }

  getApplicationsByOrganization(organizationName) {
    ApplicationBackend.getApplicationsByOrganization("admin", organizationName)
      .then((res) => {
        this.setState({
          applications: (res.msg === undefined) ? res : [],
        });
      });
  }

  getUserApplication() {
    ApplicationBackend.getUserApplication(this.state.organizationName, this.state.userName)
      .then((application) => {
        this.setState({
          application: application,
        });
      });
  }

  setReturnUrl() {
    const searchParams = new URLSearchParams(this.props.location.search);
    const returnUrl = searchParams.get("returnUrl");
    if (returnUrl !== null) {
      this.setState({
        returnUrl: returnUrl,
      });
    }
  }

  parseUserField(key, value) {
    // if ([].includes(key)) {
    //   value = Setting.myParseInt(value);
    // }
    return value;
  }

  updateUserField(key, value) {
    value = this.parseUserField(key, value);

    const user = this.state.user;
    user[key] = value;
    this.setState({
      user: user,
    });
  }

  unlinked() {
    this.getUser();
  }

  isSelf() {
    return (this.state.user.id === this.props.account?.id);
  }

  isSelfOrAdmin() {
    return this.isSelf() || Setting.isAdminUser(this.props.account);
  }

  renderAccountItem(accountItem) {
    if (!accountItem.visible) {
      return null;
    }

    const isAdmin = Setting.isAdminUser(this.props.account);

    // return (
    //   <div>
    //     {
    //       JSON.stringify({accountItem: accountItem, isSelf: isSelf, isAdmin: isAdmin})
    //     }
    //   </div>
    // )

    if (accountItem.viewRule === "Self") {
      if (!this.isSelfOrAdmin()) {
        return null;
      }
    } else if (accountItem.viewRule === "Admin") {
      if (!isAdmin) {
        return null;
      }
    }

    let disabled = false;
    if (accountItem.modifyRule === "Self") {
      if (!this.isSelfOrAdmin()) {
        disabled = true;
      }
    } else if (accountItem.modifyRule === "Admin") {
      if (!isAdmin) {
        disabled = true;
      }
    } else if (accountItem.modifyRule === "Immutable") {
      disabled = true;
    }

    if (accountItem.name === "Organization") {
      return (
        <Row style={{marginTop: "10px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Organization"), i18next.t("general:Organization - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} style={{width: "100%"}} disabled={disabled} value={this.state.user.owner} onChange={(value => {
              this.getApplicationsByOrganization(value);
              this.updateUserField("owner", value);
            })}>
              {
                this.state.organizations.map((organization, index) => <Option key={index} value={organization.name}>{organization.name}</Option>)
              }
            </Select>
          </Col>
        </Row>
      );
    } else if (accountItem.name === "ID") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel("ID", i18next.t("general:ID - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.user.id} disabled={disabled} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Name") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Name"), i18next.t("general:Name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.user.name} disabled={disabled} onChange={e => {
              this.updateUserField("name", e.target.value);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Display name") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Display name"), i18next.t("general:Display name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.user.displayName} onChange={e => {
              this.updateUserField("displayName", e.target.value);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Avatar") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Avatar"), i18next.t("general:Avatar - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Row style={{marginTop: "20px"}} >
              <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
                {i18next.t("general:Preview")}:
              </Col>
              <Col span={22} >
                <a target="_blank" rel="noreferrer" href={this.state.user.avatar}>
                  <img src={this.state.user.avatar} alt={this.state.user.avatar} height={90} style={{marginBottom: "20px"}} />
                </a>
              </Col>
            </Row>
            <Row style={{marginTop: "20px"}}>
              <CropperDiv buttonText={`${i18next.t("user:Upload a photo")}...`} title={i18next.t("user:Upload a photo")} user={this.state.user} organization={this.state.organizations.find(organization => organization.name === this.state.organizationName)} />
            </Row>
          </Col>
        </Row>
      );
    } else if (accountItem.name === "User type") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:User type"), i18next.t("general:User type - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} style={{width: "100%"}} value={this.state.user.type} onChange={(value => {this.updateUserField("type", value);})}
              options={["normal-user"].map(item => Setting.getOption(item, item))}
            />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Password") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Password"), i18next.t("general:Password - Tooltip"))} :
          </Col>
          <Col span={22} >
            <PasswordModal user={this.state.user} account={this.props.account} disabled={disabled} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Email") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Email"), i18next.t("general:Email - Tooltip"))} :
          </Col>
          <Col style={{paddingRight: "20px"}} span={11} >
            {Setting.isLocalAdminUser(this.props.account) ?
              (<Input value={this.state.user.email}
                style={{width: "280Px"}}
                disabled={disabled}
                onChange={e => {
                  this.updateUserField("email", e.target.value);
                }} />) :
              (<Select virtual={false} value={this.state.user.email}
                style={{width: "280Px"}}
                options={[Setting.getItem(this.state.user.email, this.state.user.email)]}
                disabled={disabled}
                onChange={e => {
                  this.updateUserField("email", e.target.value);
                }} />)
            }
          </Col>
          <Col span={Setting.isMobile() ? 22 : 11} >
            {/* backend auto get the current user, so admin can not edit. Just self can reset*/}
            {this.isSelf() ? <ResetModal application={this.state.application} disabled={disabled} buttonText={i18next.t("user:Reset Email...")} destType={"email"} /> : null}
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Phone") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={Setting.isMobile() ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Phone"), i18next.t("general:Phone - Tooltip"))} :
          </Col>
          <Col style={{paddingRight: "20px"}} span={11} >
            {Setting.isLocalAdminUser(this.props.account) ?
              <Input.Group compact style={{width: "280Px"}}>
                <PhoneNumberInput
                  style={{width: "30%"}}
                  value={this.state.user.countryCode}
                  onChange={(value) => {
                    this.updateUserField("countryCode", value);
                  }}
                  countryCodes={this.state.application?.organizationObj.countryCodes}
                />
                <Input value={this.state.user.phone}
                  style={{width: "70%"}}
                  disabled={disabled}
                  onChange={e => {
                    this.updateUserField("phone", e.target.value);
                  }} />
              </Input.Group>
              :
              (<Select virtual={false} value={this.state.user.phone === "" ? null : `+${Setting.getPhoneCodeFromCountryCode(this.state.user.countryCode)} ${this.state.user.phone}`}
                options={this.state.user.phone === "" ? null : [Setting.getItem(`+${Setting.getPhoneCodeFromCountryCode(this.state.user.countryCode)} ${this.state.user.phone}`, this.state.user.phone)]}
                disabled={disabled}
                style={{width: "280px"}}
                onChange={e => {
                  this.updateUserField("phone", e.target.value);
                }} />)}
          </Col>
          <Col span={Setting.isMobile() ? 24 : 11} >
            {this.isSelf() ? (<ResetModal application={this.state.application} disabled={disabled} buttonText={i18next.t("user:Reset Phone...")} destType={"phone"} />) : null}
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Country/Region") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Country/Region"), i18next.t("user:Country/Region - Tooltip"))} :
          </Col>
          <Col span={22} >
            <SelectRegionBox defaultValue={this.state.user.region} onChange={(value) => {
              this.updateUserField("region", value);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Location") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Location"), i18next.t("user:Location - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.user.location} onChange={e => {
              this.updateUserField("location", e.target.value);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Affiliation") {
      return (
        (this.state.application === null || this.state.user === null) ? null : (
          <AffiliationSelect labelSpan={(Setting.isMobile()) ? 22 : 2} application={this.state.application} user={this.state.user} onUpdateUserField={(key, value) => {return this.updateUserField(key, value);}} />
        )
      );
    } else if (accountItem.name === "Title") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Title"), i18next.t("user:Title - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.user.title} onChange={e => {
              this.updateUserField("title", e.target.value);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Homepage") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Homepage"), i18next.t("user:Homepage - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.user.homepage} onChange={e => {
              this.updateUserField("homepage", e.target.value);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Bio") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Bio"), i18next.t("user:Bio - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.user.bio} onChange={e => {
              this.updateUserField("bio", e.target.value);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Tag") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Tag"), i18next.t("user:Tag - Tooltip"))} :
          </Col>
          <Col span={22} >
            {
              this.state.application?.organizationObj.tags?.length > 0 ? (
                <Select virtual={false} style={{width: "100%"}} value={this.state.user.tag}
                  onChange={(value => {this.updateUserField("tag", value);})}
                  options={this.state.application.organizationObj.tags?.map((tag) => {
                    const tokens = tag.split("|");
                    const value = tokens[0];
                    const displayValue = Setting.getLanguage() !== "zh" ? tokens[0] : tokens[1];
                    return Setting.getOption(displayValue, value);
                  })} />
              ) : (
                <Input value={this.state.user.tag} onChange={e => {
                  this.updateUserField("tag", e.target.value);
                }} />
              )
            }
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Signup application") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Signup application"), i18next.t("general:Signup application - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} style={{width: "100%"}} disabled={disabled} value={this.state.user.signupApplication}
              onChange={(value => {this.updateUserField("signupApplication", value);})}
              options={this.state.applications.map((application) => Setting.getOption(application.name, application.name))
              } />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Roles") {
      return (
        <Row style={{marginTop: "20px", alignItems: "center"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Roles"), i18next.t("general:Roles - Tooltip"))} :
          </Col>
          <Col span={22} >
            {
              Setting.getTags(this.state.user.roles.map(role => role.name))
            }
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Permissions") {
      return (
        <Row style={{marginTop: "20px", alignItems: "center"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Permissions"), i18next.t("general:Permissions - Tooltip"))} :
          </Col>
          <Col span={22} >
            {
              Setting.getTags(this.state.user.permissions.map(permission => permission.name))
            }
          </Col>
        </Row>
      );
    } else if (accountItem.name === "3rd-party logins") {
      return (
        !this.isSelfOrAdmin() ? null : (
          <Row style={{marginTop: "20px"}} >
            <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
              {Setting.getLabel(i18next.t("user:3rd-party logins"), i18next.t("user:3rd-party logins - Tooltip"))} :
            </Col>
            <Col span={22} >
              <div style={{marginBottom: 20}}>
                {
                  (this.state.application === null || this.state.user === null) ? null : (
                    this.state.application?.providers.filter(providerItem => Setting.isProviderVisible(providerItem)).map((providerItem) =>
                      (providerItem.provider.category === "OAuth") ? (
                        <OAuthWidget key={providerItem.name} labelSpan={(Setting.isMobile()) ? 10 : 3} user={this.state.user} application={this.state.application} providerItem={providerItem} account={this.props.account} onUnlinked={() => {return this.unlinked();}} />
                      ) : (
                        <SamlWidget key={providerItem.name} labelSpan={(Setting.isMobile()) ? 10 : 3} user={this.state.user} application={this.state.application} providerItem={providerItem} onUnlinked={() => {return this.unlinked();}} />
                      )
                    )
                  )
                }
              </div>
            </Col>
          </Row>
        )
      );
    } else if (accountItem.name === "Properties") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Properties"), i18next.t("user:Properties - Tooltip"))} :
          </Col>
          <Col span={22} >
            <PropertyTable properties={this.state.user.properties} onUpdateTable={(value) => {this.updateUserField("properties", value);}} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Is admin") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Is admin"), i18next.t("user:Is admin - Tooltip"))} :
          </Col>
          <Col span={(Setting.isMobile()) ? 22 : 2} >
            <Switch disabled={disabled} checked={this.state.user.isAdmin} onChange={checked => {
              this.updateUserField("isAdmin", checked);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Is global admin") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Is global admin"), i18next.t("user:Is global admin - Tooltip"))} :
          </Col>
          <Col span={(Setting.isMobile()) ? 22 : 2} >
            <Switch disabled={disabled} checked={this.state.user.isGlobalAdmin} onChange={checked => {
              this.updateUserField("isGlobalAdmin", checked);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Is forbidden") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Is forbidden"), i18next.t("user:Is forbidden - Tooltip"))} :
          </Col>
          <Col span={(Setting.isMobile()) ? 22 : 2} >
            <Switch checked={this.state.user.isForbidden} onChange={checked => {
              this.updateUserField("isForbidden", checked);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Is deleted") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Is deleted"), i18next.t("user:Is deleted - Tooltip"))} :
          </Col>
          <Col span={(Setting.isMobile()) ? 22 : 2} >
            <Switch checked={this.state.user.isDeleted} onChange={checked => {
              this.updateUserField("isDeleted", checked);
            }} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "WebAuthn credentials") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:WebAuthn credentials"), i18next.t("user:WebAuthn credentials"))} :
          </Col>
          <Col span={22} >
            <WebAuthnCredentialTable isSelf={this.isSelf()} table={this.state.user.webauthnCredentials} updateTable={(table) => {this.updateUserField("webauthnCredentials", table);}} refresh={this.getUser.bind(this)} />
          </Col>
        </Row>
      );
    } else if (accountItem.name === "Managed accounts") {
      return (
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Managed accounts"), i18next.t("user:Managed accounts"))} :
          </Col>
          <Col span={22} >
            <ManagedAccountTable
              title={i18next.t("user:Managed accounts")}
              table={this.state.user.managedAccounts}
              onUpdateTable={(table) => {this.updateUserField("managedAccounts", table);}}
              applications={this.state.applications}
            />
          </Col>
        </Row>
      );
    }
  }

  renderUser() {
    return (
      <Card size="small" title={
        <div>
          {this.state.mode === "add" ? i18next.t("user:New User") : i18next.t("user:Edit User")}&nbsp;&nbsp;&nbsp;&nbsp;
          <Button onClick={() => this.submitUserEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" onClick={() => this.submitUserEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} onClick={() => this.deleteUser()}>{i18next.t("general:Cancel")}</Button> : null}
        </div>
      } style={(Setting.isMobile()) ? {margin: "5px"} : {}} type="inner">
        {
          this.state.application?.organizationObj.accountItems?.map(accountItem => {
            return (
              <React.Fragment key={accountItem.name}>
                {
                  this.renderAccountItem(accountItem)
                }
              </React.Fragment>
            );
          })
        }
      </Card>
    );
  }

  submitUserEdit(willExist) {
    const user = Setting.deepCopy(this.state.user);
    UserBackend.updateUser(this.state.organizationName, this.state.userName, user)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          this.setState({
            organizationName: this.state.user.owner,
            userName: this.state.user.name,
          });

          if (this.props.history !== undefined) {
            if (willExist) {
              this.props.history.push("/users");
            } else {
              this.props.history.push(`/users/${this.state.user.owner}/${this.state.user.name}`);
            }
          } else {
            if (willExist) {
              if (this.state.returnUrl) {
                window.location.href = this.state.returnUrl;
              }
            }
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          this.updateUserField("owner", this.state.organizationName);
          this.updateUserField("name", this.state.userName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteUser() {
    UserBackend.deleteUser(this.state.user)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push("/users");
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  render() {
    return (
      <div>
        {
          this.state.loading ? <Spin size="large" style={{marginLeft: "50%", marginTop: "10%"}} /> : (
            this.state.user !== null ? this.renderUser() :
              <Result
                status="404"
                title="404 NOT FOUND"
                subTitle={i18next.t("general:Sorry, the user you visited does not exist or you are not authorized to access this user.")}
                extra={<a href="/"><Button type="primary">{i18next.t("general:Back Home")}</Button></a>}
              />
          )
        }
        {
          this.state.user === null ? null :
            <div style={{marginTop: "20px", marginLeft: "40px"}}>
              <Button size="large" onClick={() => this.submitUserEdit(false)}>{i18next.t("general:Save")}</Button>
              <Button style={{marginLeft: "20px"}} type="primary" size="large" onClick={() => this.submitUserEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
              {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} size="large" onClick={() => this.deleteUser()}>{i18next.t("general:Cancel")}</Button> : null}
            </div>
        }
      </div>
    );
  }
}

export default UserEditPage;
