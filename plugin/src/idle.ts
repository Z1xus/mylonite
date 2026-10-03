export function idle(): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, 0));
}
