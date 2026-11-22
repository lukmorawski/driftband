// Active Alerts page (top navigation): what is alerting right now and the
// delivery history, for every member of the organization. The same two
// cards as in Settings > Notifications, refreshed while the page is open.
import { h, clear } from "../ui.js";
import { eventsCards } from "./notifications.js";

const REFRESH_MS = 30000;

export async function renderAlerts(mount) {
  clear(mount);
  const events = eventsCards();
  mount.append(
    h("div.section-title", h("h2", "Active Alerts")),
    h("div.stack", events.activeCard, events.logCard));
  await events.refresh();
  // stop refreshing once the page has been replaced by another view
  const timer = setInterval(() => {
    if (!events.activeCard.isConnected) { clearInterval(timer); return; }
    events.refresh();
  }, REFRESH_MS);
}
