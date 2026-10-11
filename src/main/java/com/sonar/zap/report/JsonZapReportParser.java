package com.sonar.zap.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sonar.zap.report.ZapReport.Alert;
import com.sonar.zap.report.ZapReport.Instance;
import com.sonar.zap.report.ZapReport.Site;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/** Parses the ZAP "traditional-json" report. Values may be strings or numbers depending on the ZAP version. */
public class JsonZapReportParser implements ZapReportParser {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Override
  public ZapReport parse(InputStream in) throws IOException {
    JsonNode root = MAPPER.readTree(in);
    if (root == null || !root.isObject()) {
      throw new IOException("Not a ZAP JSON report: root is not an object");
    }
    JsonNode siteNode = root.get("site");
    if (siteNode == null) {
      throw new IOException("Not a ZAP JSON report: missing 'site'");
    }
    List<Site> sites = new ArrayList<>();
    if (siteNode.isArray()) {
      siteNode.forEach(s -> sites.add(readSite(s)));
    } else {
      sites.add(readSite(siteNode));
    }
    return new ZapReport(text(root, "@version"), text(root, "@generated"), sites);
  }

  private static Site readSite(JsonNode site) {
    List<Alert> alerts = new ArrayList<>();
    JsonNode alertsNode = site.get("alerts");
    if (alertsNode != null && alertsNode.isArray()) {
      alertsNode.forEach(a -> alerts.add(readAlert(a)));
    }
    return new Site(text(site, "@name"), text(site, "@host"), alerts);
  }

  private static Alert readAlert(JsonNode a) {
    List<Instance> instances = new ArrayList<>();
    JsonNode instancesNode = a.get("instances");
    if (instancesNode != null && instancesNode.isArray()) {
      instancesNode.forEach(i -> instances.add(new Instance(
        text(i, "uri"), text(i, "method"), text(i, "param"), text(i, "attack"), text(i, "evidence"))));
    }
    String name = text(a, "name");
    if (name.isBlank()) {
      name = text(a, "alert");
    }
    return new Alert(
      text(a, "pluginid"), text(a, "alertRef"), name,
      ParseUtils.toInt(text(a, "riskcode"), 0), text(a, "confidence"),
      text(a, "desc"), text(a, "solution"), text(a, "reference"), text(a, "otherinfo"),
      ParseUtils.toInt(text(a, "cweid"), -1), ParseUtils.toInt(text(a, "wascid"), -1),
      instances);
  }

  private static String text(JsonNode node, String field) {
    JsonNode value = node.get(field);
    return value == null || value.isNull() ? "" : value.asText();
  }
}
