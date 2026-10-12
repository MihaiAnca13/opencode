import { describe, expect, test } from "bun:test"
import { EventEmitter } from "node:events"
import type { BrowserWindow, Session, WebContents } from "electron"
import { allowRendererPermissions } from "./security"

type RequestHandler = NonNullable<Parameters<Session["setPermissionRequestHandler"]>[0]>

type CheckHandler = NonNullable<Parameters<Session["setPermissionCheckHandler"]>[0]>

type Permission = Parameters<RequestHandler>[1]

// SAFETY: allowRendererPermissions reads only `webContents.id` and `details.requestingUrl`.
/* oxlint-disable anti-slop/no-chained-type-assertions -- see SAFETY above */
function sender(id: number) {
  // SAFETY: allowRendererPermissions reads only `webContents.id`.
  return { id } as unknown as WebContents
}

function requestDetails(requestingUrl: string) {
  // SAFETY: allowRendererPermissions reads only `details.requestingUrl`.
  return { requestingUrl } as unknown as Parameters<RequestHandler>[3]
}

function checkDetails(requestingUrl: string) {
  // SAFETY: allowRendererPermissions reads only `details.requestingUrl`.
  return { requestingUrl } as unknown as Parameters<CheckHandler>[3]
}
/* oxlint-enable anti-slop/no-chained-type-assertions */

function createSession() {
  let requestHandler: RequestHandler | undefined
  let checkHandler: CheckHandler | undefined

  const session = {
    setPermissionRequestHandler(handler: RequestHandler | null) {
      requestHandler = handler ?? undefined
    },
    setPermissionCheckHandler(handler: CheckHandler | null) {
      checkHandler = handler ?? undefined
    },
  }

  return {
    session,
    request(id: number, permission: Permission, requestingUrl: string) {
      if (!requestHandler) throw new Error("Missing permission request handler")
      let granted: boolean | undefined
      requestHandler(
        sender(id),
        permission,
        (allowed) => {
          granted = allowed
        },
        requestDetails(requestingUrl),
      )

      return granted
    },
    check(id: number | null, permission: Permission, requestingOrigin: string, requestingUrl = requestingOrigin) {
      if (!checkHandler) throw new Error("Missing permission check handler")

      return checkHandler(id === null ? null : sender(id), permission, requestingOrigin, checkDetails(requestingUrl))
    },
  }
}

function createWindow(id: number, session: ReturnType<typeof createSession>["session"]) {
  const events = new EventEmitter()

  // SAFETY: allowRendererPermissions reads only `win.once("closed")` and `win.webContents.{id,session}`.
  // oxlint-disable-next-line anti-slop/no-chained-type-assertions -- see SAFETY above
  const win = {
    once: events.once.bind(events),
    webContents: { id, session },
  } as unknown as BrowserWindow

  return {
    win,
    close: () => events.emit("closed"),
  }
}

describe("renderer permissions", () => {
  test.each([
    {
      name: "allows video and element fullscreen from the renderer",
      id: 1,
      permission: "fullscreen" as const,
      origin: "oc://renderer/",
      url: "oc://renderer/index.html",
      expected: true,
    },
    {
      name: "allows sanitized clipboard writes from the renderer",
      id: 1,
      permission: "clipboard-sanitized-write" as const,
      origin: "oc://renderer/",
      url: "oc://renderer/index.html",
      expected: true,
    },
    {
      name: "allows notifications from the renderer",
      id: 1,
      permission: "notifications" as const,
      origin: "oc://renderer/",
      url: "oc://renderer/index.html",
      expected: true,
    },
    {
      name: "rejects unapproved permissions from the renderer",
      id: 1,
      permission: "geolocation" as const,
      origin: "oc://renderer/",
      url: "oc://renderer/index.html",
      expected: false,
    },
    {
      name: "rejects fullscreen from non-renderer origins",
      id: 1,
      permission: "fullscreen" as const,
      origin: "https://example.com",
      url: "https://example.com/video.mp4",
      expected: false,
    },
    {
      name: "rejects fullscreen from extension asset origins",
      id: 1,
      permission: "fullscreen" as const,
      origin: "oc://extensions/",
      url: "oc://extensions/file/index.html",
      expected: false,
    },
    {
      name: "rejects fullscreen from embedded non-renderer webContents",
      id: 99,
      permission: "fullscreen" as const,
      origin: "oc://renderer/",
      url: "oc://renderer/index.html",
      expected: false,
    },
  ])("$name", ({ id, permission, origin, url, expected }) => {
    const harness = createSession()
    const first = createWindow(1, harness.session)
    allowRendererPermissions(first.win)

    expect(harness.request(id, permission, url)).toBe(expected)
    expect(harness.check(id, permission, origin, url)).toBe(expected)
    first.close()
  })

  test("keeps permissions active across multiple renderer windows and revokes closed ones", () => {
    const harness = createSession()
    const first = createWindow(10, harness.session)
    const second = createWindow(11, harness.session)

    allowRendererPermissions(first.win)
    allowRendererPermissions(second.win)

    expect(harness.request(10, "fullscreen", "oc://renderer/index.html")).toBe(true)
    expect(harness.request(11, "fullscreen", "oc://renderer/index.html")).toBe(true)
    expect(harness.check(10, "fullscreen", "oc://renderer/", "oc://renderer/index.html")).toBe(true)
    expect(harness.check(11, "fullscreen", "oc://renderer/", "oc://renderer/index.html")).toBe(true)

    second.close()
    expect(harness.request(10, "fullscreen", "oc://renderer/index.html")).toBe(true)
    expect(harness.request(11, "fullscreen", "oc://renderer/index.html")).toBe(false)

    first.close()
    expect(harness.request(10, "fullscreen", "oc://renderer/index.html")).toBe(false)
  })
})
