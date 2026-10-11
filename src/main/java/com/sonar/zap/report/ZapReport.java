package com.sonar.zap.report;

import java.util.List;

/** Format-independent view of a ZAP report. */
public record ZapReport(String version, String generated, List<Site> sites) {

  public record Site(String name, String host, List<Alert> alerts) {
  }

  public record Alert(
    String pluginId,
    String alertRef,
    String name,
    int riskCode,
    String confidence,
    String description,
    String solution,
    String reference,
    String otherInfo,
    int cweId,
    int wascId,
    List<Instance> instances) {

    /** Stable rule identifier: the ZAP plugin id, falling back to the alert reference. */
    public String ruleId() {
      if (pluginId != null && !pluginId.isBlank()) {
        return pluginId.trim();
      }
      return alertRef == null ? "" : alertRef.trim();
    }
  }

  public record Instance(String uri, String method, String param, String attack, String evidence) {
  }

  public int alertCount() {
    return sites.stream().mapToInt(s -> s.alerts().size()).sum();
  }
}
