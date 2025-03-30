/** @jsx jsx */
import { jsx, css } from "@emotion/react";
import Icon1 from "../public/svg/nav-icon-1.svg";
import Icon2 from "../public/svg/nav-icon-2.svg";
import Icon3 from "../public/svg/nav-icon-3.svg";
import IconHelp from "../public/svg/nav-icon-help.svg";
import IconStart from "../public/svg/btn-icon-start.svg";
import IconStop from "../public/svg/btn-icon-stop.svg";
import IconFolder from "../public/svg/btn-icon-folder.svg";
import { isValid, setConstProp } from "./mutils";
import { FlexFill, ResizableArea } from "./mutils-components";
import { useCallback, useEffect, useRef, useState } from "react";
import { Navigate } from "react-router";
import { Button } from "./control-button";
import { StatusList } from "./control-status-list";

const gCss = {
  board: css({
    width: "180px",
    background: "var(--c-nav-board-bg)",
    borderRight: "0.5px ridge var(--c-nav-board-outline)",
  }),
};

function NavIconButton({ icon, onClick, val, selected }) {
  const Css = {
    normal: css({
      display: "flex",
      flexWrap: "nowrap",
      alignContent: "center",
      justifyContent: "center",
      marginBottom: "4px",
      width: "40px",
      height: "40px",
      borderRadius: "8px",
      transition: "all 0.3s ease",
      "& svg": {
        width: "61%",
      },
      "& path": {
        transition: "all 0.3s ease",
        fill: "var(--c-nav-bar-icon-inactive) !important",
      },
      "&:hover": {
        background: "var(--c-nav-bar-icon-bg)",
        cursor: "pointer",
      },
      "&:hover svg path": {
        fill: "var(--c-nav-bar-icon-active) !important",
      },
    }),
    selected: selected
      ? css({
          background: "var(--c-nav-bar-icon-bg)",
          "& svg path": {
            fill: "var(--c-nav-bar-icon-active) !important",
          },
        })
      : null,
  };
  return (
    <div
      css={[Css.normal, Css.selected]}
      onClick={() => {
        if (onClick) onClick(val);
      }}
    >
      {icon}
    </div>
  );
}

function Divider() {
  const Css = css({
    width: "36px",
    height: "0.5px",
    borderRadius: "100%",
    background: "var(--c-nav-bar-div)",
    marginInline: "auto",
    marginTop: "6px",
    marginBottom: "8px",
  });
  return <div css={Css} />;
}

function NavigatorBoard({ children }) {
  return <div css={gCss.board}>{children}</div>;
}

function BoardStart() {
  const boardRef = useRef();
  const startCapture = () => {
    alert("开始抓包");
  };
  const loadFile = () => {
    alert("打开文件");
  };
  const mainCss = css({
    boxSizing: "border-box",
    userSelect: "none",
  });
  const btnsCss = css({
    display: "flex",
    flexWrap: "nowrap",
    gap: "5px",
  });
  const startBtnCss = css({
    flexGrow: "1",
  });
  const openBtnCss = css({});
  const panelCss = css({
    display: "flex",
    flexWrap: "nowrap",
    flexDirection: "column",
    paddingInline: "12px",
    paddingBlock: "11px",
    borderBottom: "0.5px ridge var(--c-nav-board-outline)",
  });
  const panelResizeCss = css({
    background: "var(--c-nav-board-outline)",
    opacity: 0,
    transition: "all 0.3s var(--t-lose-control)",
    "&:hover": {
      transition: "all 0.8s var(--t-lose-control)",
      opacity: 1,
    },
  });

  let ret = () => {
    return (
      <div css={mainCss} ref={boardRef}>
        <ResizableArea
          css_={panelCss}
          triggerCss={panelResizeCss}
          enableHeightResize={true}
          minHeight={240}

        >
          <div css={btnsCss}>
            <Button
              text="开始抓包"
              icon={<IconStart />}
              css_={startBtnCss}
              onClick={startCapture}
            />
            <Button
              icon={<IconFolder />}
              css_={openBtnCss}
              onClick={loadFile}
            />
          </div>
          <StatusList title={"本地连接 *1"}/>
        </ResizableArea>
      </div>
    );
  };
  ret.nav = "/dashboard";
  return ret;
}

function BoardDatastream() {
  let ret = () => {
    return <div>datastream</div>;
  };
  ret.nav = "/datastream";
  return ret;
}

function BoardNormalSession() {
  let ret = () => {
    return <div>normal</div>;
  };
  ret.nav = "/normalSession";
  return ret;
}

export default function NavigatorBar() {
  const layoutCss = css({
    display: "flex",
    flexWrap: "nowrap",
  });
  const mainCss = css({
    boxSizing: "border-box",
    display: "flex",
    flexWrap: "nowrap",
    flexDirection: "column",
    alignContent: "center",
    padding: "8px",
    width: "56px",
    background: "var(--c-nav-bar-bg)",
  });
  const [curboard, setCurboard] = useState(BoardStart);
  return (
    <div css={layoutCss}>
      <div css={mainCss}>
        <NavIconButton
          icon={<Icon1 />}
          val={BoardStart}
          onClick={setCurboard}
          selected={curboard?.nav == BoardStart().nav}
        />
        <Divider />
        <NavIconButton
          icon={<Icon2 />}
          val={BoardDatastream}
          onClick={setCurboard}
          selected={curboard?.nav == BoardDatastream().nav}
        />
        <NavIconButton
          icon={<Icon3 />}
          val={BoardNormalSession}
          onClick={setCurboard}
          selected={curboard?.nav == BoardNormalSession().nav}
        />
        <FlexFill />
        <NavIconButton icon={<IconHelp />} />
      </div>
      {!isValid(curboard) ? (
        <Navigate to="/home" />
      ) : (
        <Navigate to={curboard.nav} />
      )}
      <NavigatorBoard>{isValid(curboard) && curboard()}</NavigatorBoard>
    </div>
  );
}
