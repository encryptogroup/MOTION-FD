#ifndef ABYNPARTY_H
#define ABYNPARTY_H

#include <vector>
#include <memory>
#include <omp.h>
#include <fmt/format.h>

#include "utility/typedefs.h"
#include "utility/constants.h"
#include "utility/abynconfiguration.h"
#include "abynparty/abynbackend.h"
#include "gate/gate.h"
#include "share/share.h"
//#include "OTExtension/ot/ot-ext.h"

namespace ABYN {

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticSharePtr = ABYN::Shares::ArithmeticSharePtr<T>;

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticShare = ABYN::Shares::ArithmeticShare<T>;

  class ABYNParty {

  private:
    ABYNConfigurationPtr configuration_;
    ABYNBackendPtr backend_;

    //Let's make only ABYNConfiguration be copyable
    ABYNParty() = delete;

    ABYNParty(ABYNParty &abynparty) = delete;

  protected:


  public:

    ABYNParty(std::vector<PartyPtr> &parties, size_t my_id) {
      configuration_ = std::make_shared<ABYNConfiguration>(parties, my_id);
      backend_ = std::make_shared<ABYNBackend>(configuration_);
    }

    ABYNParty(std::vector<PartyPtr> &&parties, size_t my_id) :
        ABYNParty(parties, my_id) {}

    ABYNParty(std::initializer_list<PartyPtr> &list_parties, size_t my_id) {
      configuration_ = std::make_shared<ABYNConfiguration>(list_parties, my_id);
      backend_ = std::make_shared<ABYNBackend>(configuration_);
    }

    ABYNParty(std::initializer_list<PartyPtr> &&list_parties, size_t my_id) :
        ABYNParty(list_parties, my_id) {}

    ABYNParty(ABYNConfigurationPtr &configuration) : configuration_(configuration) {}

    ~ABYNParty() {
      backend_->VerifyHelloMessages();
      backend_->WaitForConnectionEnd();
      backend_->GetLogger()->LogInfo("ABYNParty has been deallocated");
    }

    ABYNConfigurationPtr GetConfiguration() { return configuration_; }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ArithmeticSharePtr<T> ShareArithmeticInput(size_t party_id, T input = 0) {
      auto p = Gates::Arithmetic::ArithmeticInputGate(input, party_id, backend_);
      auto s = std::move(p.GetOutputShare());
      auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(input)>>(s);
      return sa;
    }

    size_t GetNumOfParties() { return configuration_->GetNumOfParties(); }

    void Connect();

    void Finish();

    //TODO
    void Run(size_t repeats = 1);

    static std::vector<std::unique_ptr<ABYNParty>> GetNLocalConnectedParties(size_t num_parties, u16 port);
  };

  using ABYNPartyPtr = std::unique_ptr<ABYNParty>;

}
#endif //ABYNPARTY_H
