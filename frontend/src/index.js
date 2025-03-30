/** @jsx jsx */
import { jsx, css, Global } from "@emotion/react";
import jetbrainsMono from "../public/JetBrainsMono-Regular.woff2";
import puhuiLight from "../public/Alibaba-PuHuiTi-Light.woff2";
import puhuiRegular from "../public/Alibaba-PuHuiTi-Regular.woff2";
import puhuiMedium from "../public/Alibaba-PuHuiTi-Medium.woff2";
import React, { StrictMode, useState, useEffect } from "react";
import ReactDOM from "react-dom/client";
import {
  BrowserRouter,
  Routes,
  Route,
  NavLink,
  useNavigate,
  Outlet,
  Navigate,
} from "react-router";
import NavigatorBar from "./navigator-ui";

const GlobalCss = {
  font: css`
    @font-face {
      font-family: "puhui-light";
      src: url("${puhuiLight}") format("woff2");
    }
    @font-face {
      font-family: "puhui-regular";
      src: url("${puhuiRegular}") format("woff2");
    }
    @font-face {
      font-family: "puhui-medium";
      src: url("${puhuiMedium}") format("woff2");
    }
    @font-face {
      font-family: "jetbrains-mono";
      src: url("${jetbrainsMono}") format("woff2");
    }
    :root,
    input {
      font-family: "puhui-regular";
    }
  `,
  init: css`
    body {
      margin: 0;
    }
    body > div {
      margin: 0;
      height: 100vh;
      display: flex;
      background: var(--c-main-bg);
    }
  `,
  colorScheme: css({
    ":root": {
      "--c-default-bg": "#FFFFFF",
      "--c-main-bg": "#EFEFEF",
      "--c-main-text": "#75323B",
      "--c-title-bar-bg": "#B54240",
      "--c-title-bar-text": "#FCFAFA",
      "--c-title-bar-icon": "#EFEFEF",
      "--c-nav-bar-bg": "#75323B",
      "--c-nav-bar-icon-inactive": "#E3C3C3",
      "--c-nav-bar-icon-active": "#FAEBEB",
      "--c-nav-bar-icon-bg": "rgb(250 235 235 / 17%)",
      "--c-nav-bar-div": "rgb(173 152 150 / 35%)",
      "--c-nav-board-bg": "#F7E9E9",
      "--c-nav-board-outline": "#F0D3D3",
      "--c-nav-board-text": "#B54240",
      "--c-button-text": "#B54240",
      "--c-button-icon": "#D64242",
      "--c-button-bg": "#FFFFFF",
      "--c-scrollbar-bg": "rgb(250 232 232 / 52%)",
      "--c-scrollbar-thumb": "rgb(212 199 199 / 52%)",
      "--c-status-list-bg": "#FFFFFF",
      "--c-status-list-item-bg": "#ffffffff",
      "--c-status-list-item-bg-selected": "#F7F0F0",
      "--c-status-list-item-bg-hover": "#F7F0F0",
      "--c-status-list-item-text": "#B84A4A",
      "--c-status-list-item-ind": "#E66663",
    },
  }),
  timingFunc: css({
    ":root": {
      "--t-lose-control": "cubic-bezier(.78,-0.55,.12,1.55)",
      "--t-jump-in": "cubic-bezier(0.52,-0.39,0.89,0.25)",
      "--t-overshoot": "cubic-bezier(0.77, 0.05, 0.35, 1.29)",
    },
  }),
};

const App = () => {
  return (
    <>
      <Global styles={GlobalCss.font} />
      <Global styles={GlobalCss.init} />
      <Global styles={GlobalCss.colorScheme} />
      <Global styles={GlobalCss.timingFunc} />
      <div>
        <NavigatorBar />
        <Routes>
          <Route path="/home" element={"home"} />
          <Route path="/dashboard" element={"dashboard"} />
          <Route path="/datastream" element={"datastream"} />
          <Route path="/normalSession" element={"normalSession"} />
        </Routes>
      </div>
    </>
  );
};

// 创建根节点
const root = ReactDOM.createRoot(document.getElementById("root"));

// 渲染应用
root.render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>
);
