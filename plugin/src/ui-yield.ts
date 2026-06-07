export function yieldToObsidian(): Promise<void> {
  return new Promise((resolve) => {
    activeWindow.setTimeout(resolve, 0);
  });
}
