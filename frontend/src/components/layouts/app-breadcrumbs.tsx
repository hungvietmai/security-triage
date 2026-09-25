import { Link, useMatches } from "@tanstack/react-router";
import { Fragment } from "react";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

/** Renders `staticData.crumb` of every matched route, outermost first. */
export function AppBreadcrumbs() {
  const matches = useMatches();
  const crumbs = matches.filter((match) => match.staticData.crumb);

  return (
    <Breadcrumb>
      <BreadcrumbList>
        {crumbs.map((match, index) => {
          const Crumb = match.staticData.crumb!;
          const label = typeof Crumb === "string" ? Crumb : <Crumb />;
          const last = index === crumbs.length - 1;
          return (
            <Fragment key={match.id}>
              {index > 0 && <BreadcrumbSeparator />}
              <BreadcrumbItem className="min-w-0">
                {last ? (
                  <BreadcrumbPage className="truncate">{label}</BreadcrumbPage>
                ) : (
                  <BreadcrumbLink asChild>
                    <Link to={match.pathname}>{label}</Link>
                  </BreadcrumbLink>
                )}
              </BreadcrumbItem>
            </Fragment>
          );
        })}
      </BreadcrumbList>
    </Breadcrumb>
  );
}
