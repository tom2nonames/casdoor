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

import React from "react";
import {Alert, Avatar, Input, List, Spin} from "antd";
import {CopyOutlined, DislikeOutlined, LikeOutlined, SendOutlined} from "@ant-design/icons";
import i18next from "i18next";

const {TextArea} = Input;

class ChatBox extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      inputValue: "",
    };

    this.listContainerRef = React.createRef();
  }

  componentDidUpdate(prevProps) {
    if (prevProps.messages !== this.props.messages && this.props.messages !== undefined && this.props.messages !== null) {
      this.scrollToListItem(this.props.messages.length);
    }
  }

  handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();

      if (this.state.inputValue !== "") {
        this.send(this.state.inputValue);
        this.setState({inputValue: ""});
      }
    }
  };

  scrollToListItem(index) {
    const listContainerElement = this.listContainerRef.current;

    if (!listContainerElement) {
      return;
    }

    const targetItem = listContainerElement.querySelector(
      `#chatbox-list-item-${index}`
    );

    if (!targetItem) {
      return;
    }

    const scrollDistance = targetItem.offsetTop - listContainerElement.offsetTop;

    listContainerElement.scrollTo({
      top: scrollDistance,
      behavior: "smooth",
    });
  }

  send = (text) => {
    this.props.sendMessage(text);
    this.setState({inputValue: ""});
  };

  renderText(text) {
    const lines = text.split("\n").map((line, index) => (
      <React.Fragment key={index}>
        {line}
        <br />
      </React.Fragment>
    ));
    return <div>{lines}</div>;
  }

  renderList() {
    if (this.props.messages === undefined || this.props.messages === null) {
      return (
        <div style={{display: "flex", justifyContent: "center", alignItems: "center"}}>
          <Spin size="large" tip={i18next.t("login:Loading")} style={{paddingTop: "20%"}} />
        </div>
      );
    }

    return (
      <div ref={this.listContainerRef} style={{position: "relative", maxHeight: "calc(100vh - 140px)", overflowY: "auto"}}>
        <List
          itemLayout="horizontal"
          dataSource={[...this.props.messages, {}]}
          renderItem={(item, index) => {
            if (Object.keys(item).length === 0 && item.constructor === Object) {
              return <List.Item id={`chatbox-list-item-${index}`} style={{
                height: "160px",
                backgroundColor: index % 2 === 0 ? "white" : "rgb(247,247,248)",
                borderBottom: "1px solid rgb(229, 229, 229)",
                position: "relative",
              }} />;
            }

            return (
              <List.Item id={`chatbox-list-item-${index}`} style={{
                backgroundColor: index % 2 === 0 ? "white" : "rgb(247,247,248)",
                borderBottom: "1px solid rgb(229, 229, 229)",
                position: "relative",
              }}>
                <div style={{width: "800px", margin: "0 auto", position: "relative"}}>
                  <List.Item.Meta
                    avatar={<Avatar style={{width: "30px", height: "30px", borderRadius: "3px"}} src={item.author === `${this.props.account.owner}/${this.props.account.name}` ? this.props.account.avatar : "https://cdn.casbin.com/casdoor/resource/built-in/admin/gpt.png"} />}
                    title={
                      <div style={{fontSize: "16px", fontWeight: "normal", lineHeight: "24px", marginTop: "-15px", marginLeft: "5px", marginRight: "80px"}}>
                        {
                          !item.text.includes("#ERROR#") ? this.renderText(item.text) : (
                            <Alert message={item.text.slice("#ERROR#: ".length)} type="error" showIcon />
                          )
                        }
                      </div>
                    }
                  />
                  <div style={{position: "absolute", top: "0px", right: "0px"}}
                  >
                    <CopyOutlined style={{color: "rgb(172,172,190)", margin: "5px"}} />
                    <LikeOutlined style={{color: "rgb(172,172,190)", margin: "5px"}} />
                    <DislikeOutlined style={{color: "rgb(172,172,190)", margin: "5px"}} />
                  </div>
                </div>
              </List.Item>
            );
          }}
        />
        <div style={{
          position: "absolute",
          bottom: 0,
          left: 0,
          right: 0,
          height: "120px",
          background: "linear-gradient(transparent 0%, rgba(255, 255, 255, 0.8) 50%, white 100%)",
          pointerEvents: "none",
        }} />
      </div>
    );
  }

  renderInput() {
    return (
      <div
        style={{
          position: "fixed",
          bottom: "90px",
          width: "100%",
          display: "flex",
          justifyContent: "center",
        }}
      >
        <div style={{position: "relative", width: "760px", marginLeft: "-280px"}}>
          <TextArea
            placeholder={"Send a message..."}
            autoSize={{maxRows: 8}}
            value={this.state.inputValue}
            onChange={(e) => this.setState({inputValue: e.target.value})}
            onKeyDown={this.handleKeyDown}
            style={{
              fontSize: "16px",
              fontWeight: "normal",
              lineHeight: "24px",
              width: "770px",
              height: "48px",
              borderRadius: "6px",
              borderColor: "rgb(229,229,229)",
              boxShadow: "0 0 15px rgba(0, 0, 0, 0.1)",
              paddingLeft: "17px",
              paddingRight: "17px",
              paddingTop: "12px",
              paddingBottom: "12px",
            }}
            suffix={<SendOutlined style={{color: "rgb(210,210,217"}} onClick={() => this.send(this.state.inputValue)} />}
            autoComplete="off"
          />
          <SendOutlined
            style={{
              color: this.state.inputValue === "" ? "rgb(210,210,217)" : "rgb(142,142,160)",
              position: "absolute",
              bottom: "17px",
              right: "17px",
            }}
            onClick={() => this.send(this.state.inputValue)}
          />
        </div>
      </div>
    );
  }

  render() {
    return (
      <div>
        {
          this.renderList()
        }
        {
          this.renderInput()
        }
      </div>
    );
  }
}

export default ChatBox;
