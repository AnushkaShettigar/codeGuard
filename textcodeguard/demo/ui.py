from __future__ import annotations

from typing import Any

try:
    import gradio as gr  # type: ignore
except Exception:  # pragma: no cover
    gr = None

from textcodeguard.guard import guard


if gr is not None:
    def evaluate(code: str) -> dict[str, Any]:
        return guard(code)

    with gr.Blocks() as demo:
        gr.Markdown("# CodeGuard demo")
        code_input = gr.Textbox(label="Code to inspect", lines=12)
        output = gr.JSON(label="Verdict")
        button = gr.Button("Check")
        button.click(fn=evaluate, inputs=code_input, outputs=output)

    if __name__ == "__main__":
        demo.launch()
else:
    def _no_gradio() -> None:
        raise RuntimeError("gradio is not installed. Install requirements.txt and rerun this UI.")

    if __name__ == "__main__":
        _no_gradio()
