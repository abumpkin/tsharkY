import { useCallback, useEffect, useRef, useState } from "react";

export function isValid(value) {
  // 排除 null、undefined、0、NaN、空字符串、空对象、空数组
  if (
    value === null ||
    value === undefined ||
    value === 0 ||
    value === "" ||
    Number.isNaN(value) ||
    (typeof value === "object" && Object.keys(value).length === 0) ||
    (Array.isArray(value) && value.length === 0)
  ) {
    return false;
  }
  return true;
}

export function setConstProp(obj, name, value) {
  Object.defineProperty(obj, name, {
    value: value,
    writable: false,
    configurable: false,
    enumerable: true,
  });
}

export function useResize(elem) {
  const [entry, setEntry] = useState();
  const observer = useRef(null);
  useEffect(() => {
    observer.current = new ResizeObserver((entries) => {
      for (let i of entries) {
        setEntry(i);
        return;
      }
    });
    observer.current.observe(elem instanceof HTMLElement ? elem : elem.current);
    return () => {
      if (isValid(observer.current)) observer.current.disconnect();
    };
  }, []);
  return entry;
}

export function useDrag(elem, onDrag, deps = []) {
  const dragState = useRef({
    isDragging: false,
    dx: 0,
    dy: 0,
  });
  const origin = useRef({ x: 0, y: 0 });
  const mousedownListener = useRef(null);
  const mousemoveListener = useRef(null);
  const mouseupListener = useRef(null);
  const onDragRef = useRef();

  const htmlElem = elem instanceof HTMLElement ? elem : elem.current;
  const cleanListener = () => {
    // console.log("clean");
    if (isValid(htmlElem) && isValid(mousedownListener.current)) {
      htmlElem.addEventListener("mousedown", mousedownListener.current);
    }
    if (isValid(mousemoveListener.current)) {
      document.removeEventListener("mousemove", mousemoveListener.current);
      mousemoveListener.current = null;
    }
    if (isValid(mouseupListener.current)) {
      document.removeEventListener("mouseup", mouseupListener.current);
      mouseupListener.current = null;
    }
  };
  const mouseup = (e) => {
    cleanListener();
    dragState.current = {
      isDragging: false,
      dx: e.clientX - origin.current.x,
      dy: e.clientY - origin.current.y,
    };
    onDragRef.current?.(dragState.current);
  };
  const mousemove = (e) => {
    if (!dragState.current.isDragging) return;
    dragState.current = {
      isDragging: true,
      dx: e.clientX - origin.current.x,
      dy: e.clientY - origin.current.y,
    };
    onDragRef.current?.(dragState.current);
  };
  const mousedown = (e) => {
    e.preventDefault();
    cleanListener();
    document.addEventListener("mousemove", mousemove);
    mousemoveListener.current = mousemove;
    document.addEventListener("mouseup", mouseup);
    mouseupListener.current = mouseup;
    origin.current.x = e.clientX;
    origin.current.y = e.clientY;
    dragState.current = {
      isDragging: false,
      dx: 0,
      dy: 0,
    };
    onDragRef.current?.(dragState.current);
    dragState.current.isDragging = true;
  };

  useEffect(() => {
    onDragRef.current = onDrag;
  }, deps);
  useEffect(() => {
    if (isValid(htmlElem) && !isValid(mousedownListener.current)) {
      htmlElem.addEventListener("mousedown", mousedown);
      mousedownListener.current = mousedown;
    }
    return cleanListener;
  }, [htmlElem]);
}

export function useScroll(elem, onScroll, deps = []) {
  const scrollListener = useRef(null);
  const onScrollRef = useRef();

  const htmlElem = elem instanceof HTMLElement ? elem : elem.current;
  const cleanListener = () => {
    // console.log("clean");
    if (isValid(htmlElem) && isValid(mousedownListener.current)) {
      htmlElem.addEventListener("wheel", mousedownListener.current);
    }
  };
  const scroll = (e) => {
    e.preventDefault();
    onScrollRef.current?.({
      dx: e.deltaX,
      dy: e.deltaY,
    });
    // console.log(e)
  };

  useEffect(() => {
    onScrollRef.current = onScroll;
  }, deps);
  useEffect(() => {
    if (isValid(htmlElem) && !isValid(scrollListener.current)) {
      htmlElem.addEventListener("wheel", scroll);
      scrollListener.current = scroll;
    }
    return cleanListener;
  }, [htmlElem]);
}
