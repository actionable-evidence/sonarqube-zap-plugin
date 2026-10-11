package com.sonar.zap.web;

import com.sonar.zap.ZapConstants;
import org.sonar.api.web.page.Context;
import org.sonar.api.web.page.Page;
import org.sonar.api.web.page.Page.Scope;
import org.sonar.api.web.page.PageDefinition;

/** Registers the project page rendered by static/report_page.js. */
public class ZapPageDefinition implements PageDefinition {

  @Override
  public void define(Context context) {
    context.addPage(Page.builder(ZapConstants.PAGE_KEY)
      .setName("OWASP ZAP")
      .setScope(Scope.COMPONENT)
      .setComponentQualifiers(Page.Qualifier.PROJECT)
      .build());
  }
}
