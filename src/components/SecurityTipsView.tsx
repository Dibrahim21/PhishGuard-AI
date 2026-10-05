import { useState } from 'react';

interface SecurityTipsViewProps {
  onShowToast: (
    message: string,
    isAlert?: boolean
  ) => void;

  onNavigateToScanner?: () => void;
}

type SecurityTip = {
  id: number;
  icon: string;
  title: string;
  description: string;
  category: string;
};

export default function SecurityTipsView({
  onShowToast,
  onNavigateToScanner,
}: SecurityTipsViewProps) {

  const [selectedCategory, setSelectedCategory] =
    useState('All');

  const tips: SecurityTip[] = [

    {
      id: 1,
      icon: 'link',
      title: 'Inspect URLs Before Clicking',
      description:
        'Check the full domain name carefully. Attackers often use similar-looking domains and misleading subdomains.',
      category: 'URL Safety',
    },

    {
      id: 2,
      icon: 'password',
      title: 'Never Share Credentials',
      description:
        'Do not enter passwords, OTPs, recovery codes, or banking information on suspicious websites.',
      category: 'Account Security',
    },

    {
      id: 3,
      icon: 'verified_user',
      title: 'Check HTTPS and Domain Identity',
      description:
        'HTTPS alone does not guarantee a website is safe. Always verify the actual domain before trusting a login page.',
      category: 'Website Verification',
    },

    {
      id: 4,
      icon: 'warning',
      title: 'Watch for Urgent Messages',
      description:
        'Phishing attacks often create panic using messages about account suspension, payments, or security alerts.',
      category: 'Phishing Awareness',
    },

    {
      id: 5,
      icon: 'alternate_email',
      title: 'Verify Sender Information',
      description:
        'Inspect email addresses carefully. A legitimate company name does not guarantee that the sender is authentic.',
      category: 'Email Security',
    },

    {
      id: 6,
      icon: 'security',
      title: 'Enable Multi-Factor Authentication',
      description:
        'Use MFA whenever available to reduce the impact of stolen passwords and unauthorized account access.',
      category: 'Account Security',
    },

    {
      id: 7,
      icon: 'system_update',
      title: 'Keep Software Updated',
      description:
        'Regularly update your browser, operating system, and security tools to reduce exposure to known vulnerabilities.',
      category: 'Device Security',
    },

    {
      id: 8,
      icon: 'report',
      title: 'Report Suspicious Websites',
      description:
        'If you detect a phishing website, avoid interacting with it and report it through the appropriate security channels.',
      category: 'Incident Response',
    },

  ];

  const categories = [

    'All',

    'URL Safety',

    'Phishing Awareness',

    'Account Security',

    'Website Verification',

    'Email Security',

    'Device Security',

    'Incident Response',

  ];

  const filteredTips =
    selectedCategory === 'All'
      ? tips
      : tips.filter(
          (tip) =>
            tip.category ===
            selectedCategory
        );

  const handleUseScanner = () => {

    if (
      onNavigateToScanner
    ) {

      onNavigateToScanner();

    } else {

      onShowToast(
        'URL Scanner navigation is not configured.',
        true
      );

    }

  };

  return (

    <div className="w-full text-[#dce2f7]">

      {/* PAGE HEADER */}

      <div className="flex flex-col gap-4 mb-8 lg:flex-row lg:items-center lg:justify-between">

        <div>

          <div className="flex items-center gap-3">

            <div className="w-11 h-11 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">

              <span className="material-symbols-outlined text-emerald-400">
                lightbulb
              </span>

            </div>

            <div>

              <h1 className="text-2xl font-bold text-[#dce2f7]">
                Security Tips
              </h1>

              <p className="mt-1 text-sm text-[#8f96a8]">
                Learn how to identify, avoid, and respond to phishing threats.
              </p>

            </div>

          </div>

        </div>


        <button
          type="button"
          onClick={
            handleUseScanner
          }
          className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition-all active:scale-95"
        >

          <span className="material-symbols-outlined text-[18px]">
            travel_explore
          </span>

          Scan Suspicious URL

        </button>

      </div>


      {/* ALERT BANNER */}

      <div className="mb-6 rounded-2xl border border-purple-500/20 bg-gradient-to-r from-purple-950/30 via-[#141b2b] to-[#141b2b] p-5">

        <div className="flex items-start gap-4">

          <div className="w-11 h-11 shrink-0 rounded-xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center">

            <span className="material-symbols-outlined text-purple-300">
              shield
            </span>

          </div>

          <div>

            <h2 className="text-base font-bold text-[#dce2f7]">
              Stay Alert. Verify Before You Trust.
            </h2>

            <p className="mt-2 text-sm leading-relaxed text-[#8f96a8]">
              Phishing websites often imitate trusted brands, login portals,
              banks, and popular online services. Always inspect the domain
              before entering sensitive information.
            </p>

          </div>

        </div>

      </div>


      {/* CATEGORY FILTER */}

      <div className="mb-6 overflow-x-auto">

        <div className="flex gap-2 min-w-max">

          {categories.map(
            (category) => (

              <button
                key={category}
                type="button"
                onClick={() =>
                  setSelectedCategory(
                    category
                  )
                }
                className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
                  selectedCategory ===
                  category
                    ? 'bg-purple-600 text-white'
                    : 'bg-[#141b2b] border border-[#232a3a] text-[#8f96a8] hover:text-white hover:border-purple-500/30'
                }`}
              >

                {category}

              </button>

            )
          )}

        </div>

      </div>


      {/* TIPS GRID */}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">

        {filteredTips.map(
          (tip) => (

            <div
              key={tip.id}
              className="group rounded-2xl border border-[#232a3a] bg-[#141b2b] p-5 transition-all hover:border-purple-500/40 hover:-translate-y-0.5"
            >

              <div className="flex items-start justify-between gap-4">

                <div className="w-11 h-11 rounded-xl bg-[#191f2f] border border-[#2b3345] flex items-center justify-center group-hover:border-purple-500/30 transition-colors">

                  <span className="material-symbols-outlined text-purple-300">
                    {tip.icon}
                  </span>

                </div>


                <span className="px-2 py-1 rounded-md bg-[#0b101c] border border-[#232a3a] text-[10px] font-semibold text-[#8f96a8]">

                  {tip.category}

                </span>

              </div>


              <h3 className="mt-5 text-base font-bold text-[#dce2f7]">

                {tip.title}

              </h3>


              <p className="mt-2 text-sm leading-relaxed text-[#8f96a8]">

                {tip.description}

              </p>

            </div>

          )
        )}

      </div>


      {/* BOTTOM CTA */}

      <div className="mt-8 rounded-2xl border border-teal-500/20 bg-teal-500/5 p-6 text-center">

        <div className="w-12 h-12 mx-auto rounded-xl bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">

          <span className="material-symbols-outlined text-teal-400">
            security
          </span>

        </div>


        <h2 className="mt-4 text-lg font-bold text-[#dce2f7]">
          Found a Suspicious Website?
        </h2>


        <p className="mt-2 text-sm text-[#8f96a8]">
          Analyze the URL before interacting with the website.
        </p>


        <button
          type="button"
          onClick={
            handleUseScanner
          }
          className="mt-5 inline-flex items-center gap-2 px-5 py-3 rounded-xl bg-teal-500 hover:bg-teal-400 text-[#071411] font-bold text-sm transition-all active:scale-95"
        >

          <span className="material-symbols-outlined text-[18px]">
            search
          </span>

          Analyze URL

        </button>

      </div>

    </div>

  );

}
