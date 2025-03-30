/** @jsx jsx */
import { jsx, css } from "@emotion/react";
import { isValid } from "./mutils";

const Css = {
  main: css({
    display: "flex",
    flexWrap: "nowrap",
    justifyContent: "center",
    paddingBlock: "6px",
    paddingInline: "6px",
    borderRadius: "5.5px",
    gap: "4px",
    background: "var(--c-button-bg)",
    cursor: "pointer",
  }),
  text: css({
    fontSize: "16px",
    color: "var(--c-button-text)",
    textWrap: "nowrap",
  }),
  icon: css({
    display: "flex",
    aspectRatio: "1 / 1",
    width: "17px",
    color: "var(--c-button-icon)",
    marginBlock: "auto",
  }),
  iconOnly: css({
    marginInline: "2px",
    width: "19px",
  }),
};

export function Button({ text, icon, valid, onClick, ...others }) {
  return (
    <div css={[Css.main, others.css_]} onClick={onClick}>
      {isValid(text) && <span css={Css.text}>{text}</span>}
      {isValid(icon) && (
        <div css={[Css.icon, !isValid(text) ? Css.iconOnly : null]}>{icon}</div>
      )}
    </div>
  );
}
