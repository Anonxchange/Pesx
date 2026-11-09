(() => {
  const scriptUrl = document.currentScript?.src;
  if (!scriptUrl) return;

  const appBase = new URL(".", scriptUrl);
  const basePath = appBase.pathname.endsWith("/")
    ? appBase.pathname
    : `${appBase.pathname}/`;
  const currentPath = window.location.pathname;
  const routePath =
    currentPath === basePath.slice(0, -1)
      ? "/"
      : currentPath.startsWith(basePath)
        ? `/${currentPath.slice(basePath.length)}`
        : currentPath;
  const route = routePath.replace(/\/+$/, "") || "/";

  const staticPages = {
    "/about": "about-us",
    "/about-us.html": "about-us",
    "/team": "teams",
    "/teams.html": "teams",
    "/careers": "career",
    "/career.html": "career",
    "/blog": "blogs",
    "/blogs.html": "blogs",
  };
  const page = staticPages[route];
  if (!page || route === `/${page}`) return;

  const destination = new URL(page, appBase);
  destination.search = window.location.search;
  destination.hash = window.location.hash;
  window.location.replace(destination.href);
})();
