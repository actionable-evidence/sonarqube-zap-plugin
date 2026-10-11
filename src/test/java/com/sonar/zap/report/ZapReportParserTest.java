package com.sonar.zap.report;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sonar.zap.report.ZapReport.Alert;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ZapReportParserTest {

  private static Path resource(String name) throws Exception {
    return Path.of(ZapReportParserTest.class.getResource("/reports/" + name).toURI());
  }

  @Test
  void parsesJson() throws Exception {
    ZapReport report = ZapReportParser.parse(resource("zap.json"));

    assertThat(report.version()).isEqualTo("2.15.0");
    assertThat(report.sites()).hasSize(2);
    assertThat(report.alertCount()).isEqualTo(3);

    Alert csp = report.sites().get(0).alerts().get(0);
    assertThat(csp.ruleId()).isEqualTo("10038");
    assertThat(csp.riskCode()).isEqualTo(2);
    assertThat(csp.cweId()).isEqualTo(693);
    assertThat(csp.instances()).hasSize(2);

    Alert xss = report.sites().get(0).alerts().get(1);
    assertThat(xss.cweId()).isEqualTo(79); // numeric JSON value
    assertThat(xss.instances().get(0).param()).isEqualTo("q");

    Alert noName = report.sites().get(0).alerts().get(2);
    assertThat(noName.name()).isEqualTo("Re-examine Cache-control Directives"); // falls back to "alert"
  }

  @Test
  void parsesXml() throws Exception {
    ZapReport report = ZapReportParser.parse(resource("zap.xml"));

    assertThat(report.sites()).hasSize(2);
    assertThat(report.sites().get(1).alerts()).isEmpty(); // site without <alerts> must not stop parsing
    Alert xss = report.sites().get(0).alerts().get(0);
    assertThat(xss.ruleId()).isEqualTo("40012");
    assertThat(xss.riskCode()).isEqualTo(3);
    assertThat(xss.wascId()).isEqualTo(8);
    assertThat(xss.instances()).singleElement().satisfies(i -> assertThat(i.uri()).endsWith("/search"));
  }

  @Test
  void rejectsXmlWithDoctype() {
    String xxe = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><OWASPZAPReport>&x;</OWASPZAPReport>";
    assertThatThrownBy(() -> new XmlZapReportParser().parse(new ByteArrayInputStream(xxe.getBytes(StandardCharsets.UTF_8))))
      .isInstanceOf(IOException.class);
  }

  @Test
  void rejectsOtherFormats() {
    assertThatThrownBy(() -> new JsonZapReportParser().parse(new ByteArrayInputStream("[]".getBytes(StandardCharsets.UTF_8))))
      .isInstanceOf(IOException.class);
    assertThatThrownBy(() -> ZapReportParser.parse(Path.of("report.html"))).isInstanceOf(IOException.class);
  }
}
