import { useEffect, useRef, type KeyboardEvent, type MouseEvent } from "react";
import lottie from "lottie-web";
import { setupHomepageNativeInteractions } from "./homepage-native-interactions";

import "./homepage-native-interactions.css";

type CurrentMarketingPageProps = {
  page: string;
  children: React.ReactNode;
};

function revealElement(element: HTMLElement) {
  const computed = window.getComputedStyle(element);
  if (Number.parseFloat(computed.opacity) < 0.99 || (computed.filter && computed.filter !== "none")) {
    element.style.transition = "opacity .6s ease, filter .6s ease";
    element.style.setProperty("opacity", "1", "important");
    element.style.setProperty("filter", "none", "important");
    if (!/splide|swiper/.test(`${element.className}`) && computed.transform !== "none") {
      element.style.transition += ", transform .6s ease";
      element.style.setProperty("transform", "none", "important");
    }
  }
}

function handlePageClick(event: MouseEvent<HTMLDivElement>) {
  const target = event.target;
  if (!(target instanceof Element)) return;

  const burger = target.closest<HTMLButtonElement>(".px-burger");
  if (burger) {
    const nav = burger.closest<HTMLElement>(".px-nav");
    const open = nav?.classList.toggle("open") ?? false;
    burger.setAttribute("aria-expanded", String(open));
    return;
  }

  const dropdownButton = target.closest<HTMLButtonElement>(".px-dd-t");
  if (dropdownButton) {
    const dropdown = dropdownButton.closest<HTMLElement>(".px-dd");
    const willOpen = !dropdown?.classList.contains("open");
    dropdownButton.closest(".px-nav")?.querySelectorAll<HTMLElement>(".px-dd.open").forEach((item) => {
      item.classList.remove("open");
      item.querySelector(".px-dd-t")?.setAttribute("aria-expanded", "false");
    });
    if (willOpen) {
      dropdown?.classList.add("open");
      dropdownButton.setAttribute("aria-expanded", "true");
    }
    return;
  }

  const navLink = target.closest<HTMLAnchorElement>(".px-menu a");
  if (navLink) {
    const nav = navLink.closest<HTMLElement>(".px-nav");
    nav?.classList.remove("open");
    nav?.querySelector<HTMLButtonElement>(".px-burger")?.setAttribute("aria-expanded", "false");
    nav?.querySelectorAll<HTMLElement>(".px-dd.open").forEach((item) => {
      item.classList.remove("open");
      item.querySelector(".px-dd-t")?.setAttribute("aria-expanded", "false");
    });
  }

  const clickedMenuDropdown = target.closest<HTMLElement>(".px-dd");
  if (!clickedMenuDropdown) {
    event.currentTarget.querySelectorAll<HTMLElement>(".px-dd.open").forEach((item) => {
      item.classList.remove("open");
      item.querySelector(".px-dd-t")?.setAttribute("aria-expanded", "false");
    });
  }

  const clickedFaqItem = target.closest<HTMLElement>(".faq-item");
  if (!clickedFaqItem) {
    event.currentTarget.querySelectorAll<HTMLElement>(".faq-item.w--open").forEach((item) => {
      item.classList.remove("w--open");
      item.querySelector(".faq-question-block")?.setAttribute("aria-expanded", "false");
      const answer = item.querySelector<HTMLElement>(".faq-ans-block");
      answer?.classList.remove("w--open");
      if (answer) answer.hidden = true;
    });
  }

  const dropdownToggle = target.closest<HTMLElement>(".w-dropdown-toggle");
  if (dropdownToggle) {
    const dropdown = dropdownToggle.closest<HTMLElement>(".w-dropdown");
    const open = !dropdown?.classList.contains("w--open");
    const faqGroup = dropdown?.closest<HTMLElement>(".faq-qa-wrapper");
    faqGroup?.querySelectorAll<HTMLElement>(".faq-item.w--open").forEach((item) => {
      if (item === dropdown) return;
      item.classList.remove("w--open");
      item.querySelector(".faq-question-block")?.setAttribute("aria-expanded", "false");
      const answer = item.querySelector<HTMLElement>(".faq-ans-block");
      answer?.classList.remove("w--open");
      if (answer) answer.hidden = true;
    });
    dropdown?.classList.toggle("w--open", open);
    const answer = dropdown?.querySelector<HTMLElement>(".w-dropdown-list");
    answer?.classList.toggle("w--open", open);
    if (answer) answer.hidden = !open;
    dropdownToggle.setAttribute("aria-expanded", String(open));
    return;
  }

  const tab = target.closest<HTMLElement>("[data-w-tab]");
  const tabGroup = tab?.closest<HTMLElement>(".w-tabs");
  if (tab && tabGroup && !tab.classList.contains("w-tab-pane")) {
    event.preventDefault();
    const selected = tab.dataset.wTab;
    tabGroup.querySelectorAll<HTMLElement>(".w-tab-link").forEach((link) => {
      const active = link.dataset.wTab === selected;
      link.classList.toggle("w--current", active);
      link.setAttribute("aria-selected", String(active));
      link.tabIndex = active ? 0 : -1;
    });
    tabGroup.querySelectorAll<HTMLElement>(".w-tab-pane").forEach((pane) => {
      const active = pane.dataset.wTab === selected;
      pane.classList.toggle("w--tab-active", active);
      pane.hidden = !active;
    });
    return;
  }

  const filter = target.closest<HTMLButtonElement>("button[data-f]");
  if (filter) {
    const section = filter.closest<HTMLElement>("section");
    const cards = section?.querySelectorAll<HTMLElement>(".sp-card");
    if (!cards?.length) return;
    const value = filter.dataset.f ?? "all";
    section?.querySelectorAll<HTMLButtonElement>("button[data-f]").forEach((button) => {
      const active = button === filter;
      button.classList.toggle("on", active);
      button.setAttribute("aria-pressed", String(active));
    });
    cards.forEach((card) => {
      const text = card.textContent?.toLowerCase() ?? "";
      const price = Number(text.match(/\$\s*(\d+(?:\.\d+)?)/)?.[1] ?? Number.NaN);
      const visible =
        value === "all" ||
        (value === "popular" && /popular|best seller|hot/.test(text)) ||
        (value === "fast" && /fast|shipping/.test(text)) ||
        (value === "under50" && Number.isFinite(price) && price < 50) ||
        (value === "new" && /\bnew\b/.test(text));
      card.classList.toggle("hide", !visible);
    });
    event.preventDefault();
    return;
  }

  const anchor = target.closest<HTMLAnchorElement>("a[href='#']");
  if (anchor && anchor.textContent?.trim().toLowerCase() === "shuffle") {
    const section = anchor.closest("section");
    const row = section?.querySelector<HTMLElement>(".sp-row, .sp-list, .sp-track, .sp-cards");
    if (row) {
      const cards = Array.from(row.children);
      if (cards.length > 1) {
        const shift = 1 + Math.floor(Math.random() * (cards.length - 1));
        cards.slice(shift).concat(cards.slice(0, shift)).forEach((card) => row.appendChild(card));
      }
      event.preventDefault();
    }
  }
}

function handlePageKeyDown(event: KeyboardEvent<HTMLDivElement>) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const tab = target.closest<HTMLElement>(".w-tab-link[data-w-tab]");
  if (tab) {
    const tabGroup = tab.closest<HTMLElement>(".w-tabs");
    const tabs = Array.from(
      tabGroup?.querySelectorAll<HTMLElement>(".w-tab-link[data-w-tab]") ?? [],
    );
    const index = tabs.indexOf(tab);
    if (index < 0 || tabs.length === 0) return;

    let nextIndex: number | undefined;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
    if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = tabs.length - 1;

    if (nextIndex !== undefined) {
      event.preventDefault();
      tabs[nextIndex].focus();
      tabs[nextIndex].click();
      return;
    }

    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      tab.click();
      return;
    }
  }

  const faqToggle = target.closest<HTMLElement>(".faq-question-block.w-dropdown-toggle");
  if (faqToggle && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    faqToggle.click();
  }
}

export function CurrentMarketingPage({ page, children }: CurrentMarketingPageProps) {
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;

    const animations: ReturnType<typeof lottie.loadAnimation>[] = [];
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const homepageCleanup =
      page === "home" ? setupHomepageNativeInteractions(root, reducedMotion) : undefined;

    root.querySelectorAll<HTMLElement>('[data-animation-type="lottie"][data-src]').forEach((element) => {
      const source = element.dataset.src;
      if (!source) return;
      const path = source.startsWith("/") ? source : `/${source.replace(/^\.?\//, "")}`;
      const animation = lottie.loadAnimation({
        container: element,
        renderer: element.dataset.renderer === "canvas" ? "canvas" : "svg",
        path,
        loop: element.dataset.loop === "1",
        autoplay: !reducedMotion && element.dataset.autoplay !== "0",
        rendererSettings: { preserveAspectRatio: "xMidYMid meet" },
      });
      if (element.dataset.direction === "-1") animation.setDirection(-1);
      animations.push(animation);
    });

    const hidden = Array.from(root.querySelectorAll<HTMLElement>("[data-w-id]")).filter((element) => {
      const style = window.getComputedStyle(element);
      return Number.parseFloat(style.opacity) < 0.99 || (style.filter && style.filter !== "none");
    });

    let observer: IntersectionObserver | undefined;
    if (reducedMotion || !("IntersectionObserver" in window)) {
      hidden.forEach(revealElement);
    } else {
      const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          revealElement(entry.target as HTMLElement);
          revealObserver.unobserve(entry.target);
        });
      }, { threshold: 0.12 });
      observer = revealObserver;
      hidden.forEach((element) => revealObserver.observe(element));
    }

    return () => {
      observer?.disconnect();
      animations.forEach((animation) => animation.destroy());
      homepageCleanup?.();
    };
  }, [page]);

  return (
    <div
      ref={rootRef}
      className={`export-page current-source-page current-source-page-${page}`}
      data-current-source-page={page}
      onClick={handlePageClick}
      onKeyDown={handlePageKeyDown}
    >
      {children}
    </div>
  );
}
