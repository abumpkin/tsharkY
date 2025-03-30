/** @jsx jsx */
import { jsx, css } from "@emotion/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { isValid, setConstProp } from "./mutils";

export function FlexFill() {
  return (
    <div
      style={{
        flexGrow: "1",
      }}
    />
  );
}

export function ResizableArea({
  enableWidthResize = false,
  enableHeightResize = false,
  triggerRange = 3,
  triggerCss,
  initHeight = null,
  initWidth = null,
  minHeight = 0,
  minWidth = 0,
  maxHeight,
  maxWidth,
  children,
  onResize,
  css_,
}) {
  const dom = useRef();
  const [w, setW] = useState(initWidth);
  const [h, setH] = useState(initHeight);
  const Css = css({
    boxSizing: "border-box",
    width: `${w}px`,
    height: `${h}px`,
    minHeight: `${minHeight}px`,
    minWidth: `${minWidth}px`,
    maxHeight: `${maxHeight}px`,
    maxWidth: `${maxWidth}px`,
  });
  const wrapperCss = css({
    height: `${h}px`,
    width: `${w}px`,
    position: "relative",
  });
  const dragCss = css({
    position: "absolute",
  });
  useEffect(() => {
    setH(dom.current.offsetHeight);
    setW(dom.current.offsetWidth);
    if (w < minWidth) setW(minWidth);
    if (h < minHeight) setH(minHeight);
  }, [setH, setW]);
  const startPos = useRef(0);
  const origin = useRef(0);
  const isDragging = useRef(false);
  const mousemoveListener = useRef(null);
  const mouseupListener = useRef(null);
  const cleanListener = () => {
    // console.log("l1:", mouseupListener, "l2", mousemoveListener);
    if (isValid(mousemoveListener.current)) {
      document.removeEventListener("mousemove", mousemoveListener.current);
      mousemoveListener.current = null;
    }
    if (isValid(mouseupListener.current)) {
      document.removeEventListener("mouseup", mouseupListener.current);
      mouseupListener.current = null;
    }
  };
  useEffect(() => {
    return cleanListener;
  }, []);
  const EnableH = ({ children }) => {
    const rangeCss = css({
      bottom: "0",
      width: "100%",
      height: `${triggerRange}px`,
      cursor: "ns-resize",
    });
    const mouseup = (e) => {
      isDragging.current = false;
      cleanListener();
    };
    const mousemove = (e) => {
      if (!isDragging.current) return;
      let val = h + e.clientY - startPos.current;
      if (val >= minHeight) {
        setH(val);
        onResize?.(w, val);
      }
    };
    const mousedown = (e) => {
      e.preventDefault();
      startPos.current = e.clientY;
      origin.current = h;
      cleanListener();
      isDragging.current = true;
      document.addEventListener("mousemove", mousemove);
      mousemoveListener.current = mousemove;
      document.addEventListener("mouseup", mouseup);
      mouseupListener.current = mouseup;
    };
    if (enableHeightResize)
      return (
        <div
          css={[dragCss, rangeCss, triggerCss]}
          onMouseDown={mousedown}
        ></div>
      );
    return children;
  };
  function EnableW({ children }) {
    const rangeCss = css({
      right: "0",
      height: "100%",
      width: `${triggerRange}px`,
      cursor: "ew-resize",
    });
    const mouseup = (e) => {
      isDragging.current = false;
      cleanListener();
    };
    const mousemove = (e) => {
      if (!isDragging.current) return;
      let val = w + e.clientX - startPos.current;
      if (val >= minWidth) {
        setW(val);
        onResize?.(val, h);
      }
    };
    const mousedown = (e) => {
      e.preventDefault();
      startPos.current = e.clientX;
      origin.current = w;
      cleanListener();
      isDragging.current = true;
      document.addEventListener("mousemove", mousemove);
      mousemoveListener.current = mousemove;
      document.addEventListener("mouseup", mouseup);
      mouseupListener.current = mouseup;
    };
    if (enableWidthResize)
      return (
        <div
          css={[dragCss, rangeCss, triggerCss]}
          onMouseDown={mousedown}
        ></div>
      );
    return children;
  }
  return (
    <div className="resizable">
      <div css={wrapperCss}>
        <EnableH />
        <EnableW />
        <div css={[css_, Css]} ref={dom}>
          {children}
        </div>
      </div>
    </div>
  );
}
