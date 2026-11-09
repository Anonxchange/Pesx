import { useEffect, useState, type FormEvent } from "react";
import { Link, useLocation } from "wouter";
import { useAuth } from "@/lib/auth-context";
import { Search, ShoppingCart } from "@/lib/icons";
import { CartSheet } from "@/components/shop/CartSheet";

const marketplace = [
  { title: "Gift Cards", detail: "Shopping, gaming, streaming", href: "/gift-cards" },
  { title: "Mobile Top Up", detail: "Airtime and data, anywhere", href: "/wallet/mobile-topup" },
  { title: "Physical Products", detail: "Electronics, fashion, home", href: "/shop" },
];

const resources = [
  { title: "FAQ", detail: "Answers to common questions", href: "/support" },
  { title: "Blog", detail: "News and guides", href: "/blogs" },
];

export function AppHeader() {
  const [location, setLocation] = useLocation();
  const { user } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [scrolled, setScrolled] = useState(false);
  const openCartFromUrl = new URLSearchParams(window.location.search).get("openCart") === "1";
  const walletHref = user ? "/wallet" : "/signin?redirect=%2Fwallet";

  useEffect(() => {
    const update = () => setScrolled(window.scrollY > 30);
    update();
    window.addEventListener("scroll", update, { passive: true });
    return () => window.removeEventListener("scroll", update);
  }, []);

  useEffect(() => {
    setMenuOpen(false);
    setOpenDropdown(null);
    setSearchOpen(false);
  }, [location]);

  useEffect(() => {
    if (!openCartFromUrl) return;
    const url = new URL(window.location.href);
    url.searchParams.delete("openCart");
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }, [openCartFromUrl]);

  const closeMenu = () => {
    setMenuOpen(false);
    setOpenDropdown(null);
    setSearchOpen(false);
  };
  const submitSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const query = searchQuery.trim();
    setLocation(query ? `/shop?search=${encodeURIComponent(query)}` : "/shop");
    closeMenu();
  };
  const dropdown = (name: string, links: typeof marketplace) => (
    <div className={`px-dd${openDropdown === name ? " open" : ""}`} key={name}>
      <button
        className="px-dd-t"
        type="button"
        aria-expanded={openDropdown === name}
        onClick={() => setOpenDropdown(current => current === name ? null : name)}
      >
        {name}<i aria-hidden="true" />
      </button>
      <div className="px-dd-l">
        {links.map(link => (
          <Link key={link.title} href={link.href} onClick={closeMenu}>
            <b>{link.title}</b><small>{link.detail}</small>
          </Link>
        ))}
      </div>
    </div>
  );

  return (
    <header className={`px-nav px-nav-with-tools${scrolled ? " scrolled" : ""}`} id="pxnav">
      <div className="px-nav-in">
        <Link className="px-logo" href="/" onClick={closeMenu} data-testid="link-home-header">
          <span className="px-logo-mark">p</span><span>pexly</span>
        </Link>
        <nav className={`px-menu${menuOpen ? " open" : ""}`} id="pxmenu" aria-label="Main">
          {dropdown("Marketplace", marketplace)}
          <Link className="px-l" href="/#how-it-works" onClick={closeMenu}>How it works</Link>
          <Link className="px-l" href="/gift-cards" onClick={closeMenu}>Categories</Link>
          {dropdown("Resources", resources)}
          <div className="px-mob-btns">
            <Link className="px-btn ghost" href={walletHref} onClick={closeMenu}>Connect Wallet</Link>
            <Link className="px-btn solid" href="/gift-cards" onClick={closeMenu}>Start Shopping</Link>
          </div>
        </nav>
        <div className="px-tools" aria-label="Shopping tools">
          <button
            className="px-tool-search"
            type="button"
            aria-label="Search products"
            aria-expanded={searchOpen}
            aria-controls="px-header-search-panel"
            onClick={() => {
              setMenuOpen(false);
              setSearchOpen(open => !open);
            }}
          >
            <Search aria-hidden="true" />
            <span>Search</span>
          </button>
          <CartSheet
            initiallyOpen={openCartFromUrl}
            renderTrigger={(itemCount) => (
              <button
                className="px-tool-cart"
                type="button"
                aria-label={`Open shop cart, ${itemCount} ${itemCount === 1 ? "item" : "items"}`}
              >
                <ShoppingCart aria-hidden="true" />
                <span className="px-tool-cart-count" aria-hidden="true">{itemCount}</span>
              </button>
            )}
          />
        </div>
        <div className="px-right">
          <Link className="px-btn ghost" href={walletHref}>Connect Wallet</Link>
          <Link className="px-btn solid" href="/gift-cards">Start Shopping</Link>
        </div>
        <button
          className="px-burger"
          type="button"
          aria-label="Menu"
          aria-expanded={menuOpen}
          onClick={() => {
            setSearchOpen(false);
            setMenuOpen(open => !open);
          }}
        >
          <span /><span /><span />
        </button>
      </div>
      {searchOpen && (
        <div className="px-search-panel" id="px-header-search-panel">
          <form className="px-search-form" role="search" aria-label="Search Pexly products" onSubmit={submitSearch}>
            <Search aria-hidden="true" />
            <input
              autoFocus
              type="search"
              aria-label="Search products"
              placeholder="Search products..."
              value={searchQuery}
              onChange={event => setSearchQuery(event.target.value)}
            />
            <button className="px-search-submit" type="submit">Search</button>
          </form>
        </div>
      )}
    </header>
  );
}
