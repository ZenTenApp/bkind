export default {
  lang: 'en-US',
  title: 'B Kind',
  description: 'a framework for making Nostr relays',
  themeConfig: {
    logo: '/logo.png',
    nav: [
      {text: 'Home', link: '/'},
      {text: 'Why', link: '/why'},
      {text: 'Docs', link: '/getting-started'},
      {text: 'Source', link: 'https://github.com/ZenTenApp/bkind'}
    ],
    sidebar: [
      {
        text: 'Core Concepts',
        items: [
          { text: 'Event Storage', link: '/core/eventstore' },
          { text: 'Authentication', link: '/core/auth' },
          { text: 'HTTP Integration', link: '/core/embed' },
          { text: 'Request Routing', link: '/core/routing' },
          { text: 'Management API', link: '/core/management' },
          { text: 'Media Storage (Blossom)', link: '/core/blossom' },
        ]
      },
      {
        text: 'Cookbook',
        items: [
          { text: 'Search', link: '/cookbook/search' },
          { text: 'Dynamic Relays', link: '/cookbook/dynamic' },
          { text: 'Generating Events Live', link: '/cookbook/custom-live-events' },
          { text: 'Custom Stores', link: '/cookbook/custom-stores' },
          { text: 'Using something like Google Drive', link: '/cookbook/google-drive' },
          { text: 'B Kind: a Kind-4-Only DM Relay', link: '/cookbook/dm-only-relay' },
          { text: 'Configuring a Relay', link: '/cookbook/configuration' },
          { text: 'Deploying a Relay on Ubuntu', link: '/cookbook/deploying' },
          { text: 'Deploying with Docker', link: '/cookbook/docker' },
        ]
      }
    ],
    editLink: {
      pattern: 'https://github.com/ZenTenApp/bkind/edit/master/docs/:path'
    }
  },
  head: [['link', {rel: 'icon', href: '/logo.png'}]],
  cleanUrls: true
}
