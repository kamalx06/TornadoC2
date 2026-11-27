// jsdom has no layout engine. Enough of ResizeObserver for the dock to
// mount; sizes stay at the declared defaults.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
if (!('ResizeObserver' in globalThis)) {
  ;(globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver =
    ResizeObserverStub
}
if (!('PointerEvent' in globalThis)) {
  ;(globalThis as unknown as { PointerEvent: unknown }).PointerEvent =
    globalThis.MouseEvent
}
if (!window.HTMLElement.prototype.scrollIntoView) {
  window.HTMLElement.prototype.scrollIntoView = () => undefined
}
