/** @jsx jsx */
import { jsx, css } from "@emotion/react";
import { isValid, useDrag, useResize, useScroll } from "./mutils";
import { useCallback, useEffect, useRef, useState } from "react";

/**
 *
 * @param {Object} props
 * @param {number} props.status 范围 0-1
 * @returns
 */
function ListItem({ id, title, status, selected, onClick }) {
  const itemSelectedCss = css({
    background: "var(--c-status-list-item-bg-selected)",
  });
  const itemCss = css({
    height: "22px",
    background: "var(--c-status-list-item-bg)",
    display: "flex",
    color: "var(--c-status-list-item-text)",
    fontSize: "12px",
    borderRadius: "4.5px",
    paddingInline: "4px",
    alignItems: "center",
    gap: "8px",
    transition: "all 0.3s ease",
    "&:hover": {
      background: "var(--c-status-list-item-bg-hover)",
    },
  });
  const indCss = css({
    width: "3px",
    height: "12px",
    background: "var(--c-status-list-item-ind)",
    borderRadius: "1.5px",
    filter: "brightness(0.6)", // 0.8-1.4
  });
  return (
    <div
      css={[itemCss, selected == id && itemSelectedCss]}
      className="title-bar"
      onClick={(e) => onClick(e, id)}
    >
      <span css={indCss} className="indicator" />
      <span>{title}</span>
    </div>
  );
}

function ScrollBar({
  wheelElem,
  contentSize = 0,
  windowSize = 0,
  rate,
  scrollAvailableRef,
  contentAvailableRef,
  isDraggingRef,
  cssThumb,
  cssScrollbar,
}) {
  const scrollbarRef = useRef(null);
  const scrollThumbRef = useRef(null);
  const resize = useResize(scrollbarRef);
  const scrollbarHeight = useRef();
  const [scrollRate, setScrollRate] = rate;
  const [thumbHeight, setThumbHeight] = useState(0);
  const isDragging = useRef(false);
  const elem =
    wheelElem instanceof HTMLElement ? wheelElem : wheelElem?.current;
  // 计算滚动条高度
  function resizeScrollbarHeight() {
    if (contentSize > windowSize) {
      const ratio = windowSize / contentSize;
      setThumbHeight(ratio * scrollbarRef.current.clientHeight);
    } else {
      setThumbHeight(0);
    }
    scrollbarHeight.current = scrollbarRef.current.clientHeight;
    // console.log(contentSize, windowSize);
  }
  useEffect(() => {
    resizeScrollbarHeight();
  }, [resize]);

  // 处理滚动条拖动
  const scrollAvailable = thumbHeight
    ? scrollbarHeight.current - thumbHeight
    : 0;
  const oriPos = useRef(0);
  useDrag(
    scrollThumbRef,
    (state) => {
      isDragging.current = state.isDragging;
      if (!state.isDragging) oriPos.current = scrollAvailable * scrollRate;
      else {
        let calcPos = oriPos.current + state.dy;
        if (calcPos < 0) calcPos = 0;
        if (calcPos > scrollAvailable) calcPos = scrollAvailable;
        requestAnimationFrame(() => setScrollRate(calcPos / scrollAvailable));
      }
    },
    [resize, scrollRate, scrollAvailable]
  );

  // 处理鼠标滚轮
  const contentAvailable = scrollAvailable ? contentSize - windowSize : 0;
  // console.log(contentAvailable);
  useScroll(
    isValid(elem) ? elem : scrollbarRef,
    (state) => {
      // console.log(state.dy, contentAvailable);
      if (isValid(contentAvailable)) {
        oriPos.current = contentAvailable * scrollRate;
        let calcPos = oriPos.current + state.dy;
        if (calcPos < 0) calcPos = 0;
        if (calcPos > contentAvailable) calcPos = contentAvailable;
        requestAnimationFrame(() => setScrollRate(calcPos / contentAvailable));
      }
    },
    [resize, scrollRate, contentAvailable]
  );
  if (isValid(scrollAvailableRef)) scrollAvailableRef.current = scrollAvailable;
  if (isValid(contentAvailableRef))
    contentAvailableRef.current = contentAvailable;
  if (isValid(isDraggingRef)) {
    isDraggingRef.current = isDragging.current;
  }
  // 回调
  useEffect(() => {
    setScrollRate?.(scrollRate);
  }, [scrollRate]);

  const scrollbarCss = css({
    right: "3px",
    top: "4px",
    bottom: "4px",
    width: "6px",
    background: "var(--c-scrollbar-bg)",
    borderRadius: "4px",
    cursor: "pointer",
    transition: "filter 0.2s",
    filter: "saturate(0.5)",
    position: "absolute",
    "&:hover": {
      filter: "saturate(1)",
    },
  });
  const thumbCss = css({
    height: `${thumbHeight}px`,
    width: "100%",
    background: "var(--c-scrollbar-thumb)",
    borderRadius: "4px",
    cursor: "ns-resize",
    transform: `translateY(${scrollAvailable * scrollRate}px)`,
    transition: !isDragging.current && "transform 0.3s ease",
  });
  return (
    <div
      css={[scrollbarCss, cssScrollbar]}
      ref={scrollbarRef}
      className="scrollbar"
    >
      <div css={[thumbCss, cssThumb]} ref={scrollThumbRef} className="thumb" />
    </div>
  );
}

export function StatusList({ title, children, css_ }) {
  const containerRef = useRef(null);
  const contentRef = useRef(null);
  const contentAreaRef = useRef(null);
  const isDragging = useRef(false);
  const scrollAvailableRef = useRef();
  const contentAvailableRef = useRef();

  const [scrollRate, setScrollRate] = useState(0);
  const [contentSize, setContentSize] = useState(0);
  const [windowSize, setWindowSize] = useState(0);
  const [selectedItem, setSelectedItem] = useState(null);
  const [items, setItems] = useState([
    { title: "本地连接 *1", status: "1" },
    { title: "2", status: "1" },
    { title: "3", status: "1" },
    { title: "4", status: "1" },
    { title: "5", status: "1" },
    { title: "6", status: "1" },
    { title: "7", status: "1" },
    { title: "8", status: "1" },
  ]);

  const resize = useResize(containerRef);
  useEffect(() => {
    setContentSize(contentRef.current?.offsetHeight);
    setWindowSize(contentAreaRef.current?.clientHeight);
  }, [resize, contentRef, contentAreaRef]);

  const itemClick = (e, id) => {
    setSelectedItem(id);
  };

  // 样式
  const containerCss = css({
    flexGrow: "1",
    boxSizing: "border-box",
    marginTop: "8px",
    marginBottom: "2px",
    paddingBlock: "4px",
    paddingLeft: "5px",
    paddingRight: "13px",
    minHeight: "174px",
    background: "var(--c-status-list-bg)",
    borderRadius: "6px",
    position: "relative",
    overflow: "hidden",
  });
  const contentAreaCss = css({
    height: "100%",
    overflow: "hidden",
  });
  const contentCss = css({
    display: "flex",
    flexDirection: "column",
    gap: "3px",
    transform: `translateY(-${contentAvailableRef.current * scrollRate}px)`,
    transition: !isDragging.current && "transform 0.3s ease",
  });
  // console.log(
  //   scrollRate,
  //   contentAvailableRef.current,
  //   contentAvailableRef.current * scrollRate
  // );

  return (
    <div
      css={[containerCss, css_]}
      ref={containerRef}
      className="scroll-container"
    >
      <div css={contentAreaCss} ref={contentAreaRef}>
        {/* 可滚动内容 */}
        <div css={contentCss} ref={contentRef} className="scroll-content">
          {/* 列表 */}
          {items.map((i, id) => (
            <ListItem
              id={id}
              key={i.title}
              title={i.title}
              status={i.status}
              onClick={itemClick}
              selected={selectedItem}
            />
          ))}
        </div>
      </div>

      {/* 自定义滚动条 */}
      <ScrollBar
        wheelElem={contentRef}
        isDraggingRef={isDragging}
        contentSize={contentSize}
        windowSize={windowSize}
        rate={[scrollRate, setScrollRate]}
        contentAvailableRef={contentAvailableRef}
        scrollAvailableRef={scrollAvailableRef}
      />
    </div>
  );
}
