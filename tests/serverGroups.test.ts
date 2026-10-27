import { describe, expect, it } from "vitest";
import { countryServers, groupByCountry, serverLabel } from "../src/shared/serverGroups";
import type { TunnelServer } from "../src/shared/contracts";

function server(id: string, name: string, host: string, protocol = "vless", countryCode = "DE"): TunnelServer {
  return { id, tag: id, name, countryCode, outbound: { protocol, settings: { vnext: [{ address: host, port: 443 }] } } };
}

describe("server list by country", () => {
  it("reads the server label from the host remark", () => {
    expect(serverLabel("🇩🇪 Германия · Франкфурт", "DE")).toBe("Франкфурт");
    expect(serverLabel("🇩🇪 Германия | Нюрнберг 2", "DE")).toBe("Нюрнберг 2");
    expect(serverLabel("🇩🇪 Germany Frankfurt", "DE")).toBe("Frankfurt");
    expect(serverLabel("🇩🇪 🚀 Prime", "DE")).toBe("Prime");
    expect(serverLabel("🇩🇪 Германия", "DE")).toBeNull();
    expect(serverLabel("🇩🇪 🛡️ Hysteria2", "DE")).toBeNull();
    expect(serverLabel("🇩🇪 TUIC", "DE")).toBeNull();
    expect(serverLabel("🇩🇪 Германия VLESS Reality", "DE")).toBeNull();
  });

  it("puts every server of a country under one card", () => {
    const countries = groupByCountry([
      server("de1-vless", "🇩🇪 Германия · Франкфурт", "de1.example.net"),
      server("fi1", "🇫🇮 Финляндия", "fi1.example.net", "vless", "FI"),
      server("de1-hy2", "🇩🇪 🛡️ Hysteria2", "de1.example.net", "hysteria2"),
      server("de2", "🇩🇪 Германия · Нюрнберг", "de2.example.net"),
    ]);
    expect(countries.map((country) => country.countryCode)).toEqual(["DE", "FI"]);
    expect(countries[0]!.nodes.map((node) => [node.label, node.variants.map((variant) => variant.id)])).toEqual([
      ["Франкфурт", ["de1-vless", "de1-hy2"]],
      ["Нюрнберг", ["de2"]],
    ]);
    expect(countries[1]!.nodes[0]).toMatchObject({ label: "Сервер 1", labelled: false });
  });

  it("numbers servers without a label and repeated labels", () => {
    const countries = groupByCountry([
      server("a", "🇩🇪 Германия", "a.example.net"),
      server("b", "🇩🇪 Германия", "b.example.net"),
      server("c", "🇩🇪 Германия · Франкфурт", "c.example.net"),
      server("d", "🇩🇪 Германия · Франкфурт", "d.example.net"),
    ]);
    expect(countries[0]!.nodes.map((node) => node.label)).toEqual(["Сервер 1", "Сервер 2", "Франкфурт", "Франкфурт 2"]);
  });

  it("keeps home exits, unknown countries and other protocols on cards of their own", () => {
    const countries = groupByCountry([
      server("home", "🏠 Дом", "home.example.net", "vless", "DE"),
      server("trojan", "🇩🇪 Trojan", "t.example.net", "trojan"),
      server("unknown", "Сервер", "u.example.net", "vless", ""),
      server("de", "🇩🇪 Германия", "de.example.net"),
    ]);
    expect(countries.map((country) => [country.countryCode, country.nodes.map((node) => node.label)])).toEqual([
      ["", ["🏠 Дом"]],
      ["", ["🇩🇪 Trojan"]],
      ["", ["Сервер"]],
      ["DE", ["Сервер 1"]],
    ]);
  });

  it("lists every variant of a country for the automatic choice", () => {
    const servers = [
      server("de1", "🇩🇪 Германия · Франкфурт", "de1.example.net"),
      server("fi1", "🇫🇮 Финляндия", "fi1.example.net", "vless", "FI"),
      server("de2", "🇩🇪 Германия · Нюрнберг", "de2.example.net"),
    ];
    expect(countryServers(servers, "de").map((item) => item.id)).toEqual(["de1", "de2"]);
    expect(countryServers(servers, "")).toEqual([]);
  });
});
