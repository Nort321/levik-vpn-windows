import { describe, expect, it } from "vitest";
import { parseAccountNotices } from "../src/main/platform/accountNotices";
import { EventStreamParser } from "../src/main/platform/liveEvents";

describe("account notices", () => {
  it("reads notices and skips broken ones", () => {
    const notices = parseAccountNotices([
      { id: "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b", kind: "subscription_expiring", title: "Подписка закончится через 3 дня",
        body: "Продлите заранее.", target: "/dashboard/plans", createdAt: "2026-10-15T07:00:00Z" },
      { id: "4a2d3c5b-6e7f-4081-9bac-1d2e3f4a5b6c", kind: "weather", title: "Новое", body: "Что-то новое", target: "https://evil.example" },
      { id: "not-a-uuid", title: "x", body: "y", target: "/dashboard" },
      { id: "5b3e4d6c-7f80-4192-acbd-2e3f4a5b6c7d", title: "", body: "y" },
      { id: "6c4f5e7d-8091-42a3-bdce-3f4a5b6c7d8e", title: 7, body: "y" },
      "nonsense",
      null,
    ]);
    expect(notices.map((notice) => notice.cabinet)).toEqual(["/dashboard/plans", "/dashboard"]);
    expect(notices[0]?.title).toBe("Подписка закончится через 3 дня");
    expect(parseAccountNotices({ notifications: [] })).toEqual([]);
  });

  it("knows the notifications event", () => {
    expect(new EventStreamParser().push("event: notifications\ndata: {}\n\n")).toEqual(["notifications"]);
  });
});
