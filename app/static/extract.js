document.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  const target = button.dataset.copyTarget;
  if (target || button.dataset.copyValue !== undefined) {
    const value = target ? document.getElementById(target)?.value : button.dataset.copyValue;
    if (value === undefined) return;
    try {
      await navigator.clipboard.writeText(value.trim());
      button.textContent = "Copied";
    } catch {
      button.textContent = "Select Text to Copy";
      if (target) document.getElementById(target)?.select();
    }
  }
  if (button.dataset.loadImage) {
    const image = document.createElement("img");
    image.src = button.dataset.loadImage;
    image.alt = "Report image";
    image.referrerPolicy = "no-referrer";
    image.style.maxWidth = "100%";
    button.parentElement.querySelector(".image-preview").replaceChildren(image);
    button.disabled = true;
  }
});
